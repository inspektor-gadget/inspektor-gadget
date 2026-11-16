// Copyright 2025 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package otelprofiles

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pprofile/pprofileotlp"
	"google.golang.org/grpc"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/testing/gadget-context"
)

// mockGRPCClient is a wrapper around the real client that captures Export calls
type mockGRPCClient struct {
	pprofileotlp.GRPCClient
	mu        sync.Mutex
	exportReq []pprofileotlp.ExportRequest
}

func (m *mockGRPCClient) Export(ctx context.Context, request pprofileotlp.ExportRequest, opts ...grpc.CallOption) (pprofileotlp.ExportResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.exportReq = append(m.exportReq, request)

	return pprofileotlp.NewExportResponse(), nil
}

type test struct {
	mockClient *mockGRPCClient
	op         *otelProfilesOperator
	gadgetCtx  *gadgetcontext.MockGadgetContext
	opInst     *otelProfilesOperatorInstance
	ds         datasource.DataSource
}

func initTest(t *testing.T) *test {
	t.Helper()

	mockClient := &mockGRPCClient{}

	// Create operator instance with mock client
	op := &otelProfilesOperator{
		clients:  map[string]pprofileotlp.GRPCClient{"test-exporter": mockClient},
		callOpts: map[string][]grpc.CallOption{},
	}

	opInst := &otelProfilesOperatorInstance{
		o:        op,
		mappings: map[string]string{"test-datasource": "test-exporter"},
	}

	ds, err := datasource.New(datasource.TypeArray, "test-datasource")
	require.NoError(t, err)

	gadgetContext := &gadgetcontext.MockGadgetContext{
		Ctx: context.Background(),
		DataSources: map[string]datasource.DataSource{
			"test-datasource": ds,
		},
		Log: logger.DefaultLogger(),
	}

	return &test{
		mockClient: mockClient,
		op:         op,
		gadgetCtx:  gadgetContext,
		opInst:     opInst,
		ds:         ds,
	}
}

func TestOtelProfilesOperator(t *testing.T) {
	t.Parallel()

	const stackField1Name = "my_stack"
	const stackField2Name = "my_stack2"
	const valueFieldName = "my_value"
	const profilesType = "profiles_type"
	const profilesUnit = "profiles_unit"

	tests := []struct {
		name                string
		profilesName        string
		expectedProfileName string
	}{
		{
			name:                "explicit profile name",
			profilesName:        "my_profile",
			expectedProfileName: "my_profile",
		},
		{
			name:                "default to datasource name",
			profilesName:        "",
			expectedProfileName: "test-datasource",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tt := initTest(t)

			tt.ds.AddAnnotation(stackFieldsAnnotation, stackField1Name+","+stackField2Name)
			tt.ds.AddAnnotation(valueFieldAnnotation, valueFieldName)
			if tc.profilesName != "" {
				tt.ds.AddAnnotation(profilesNameAnnotation, tc.profilesName)
			}
			tt.ds.AddAnnotation(profilesTypeAnnotation, profilesType)
			tt.ds.AddAnnotation(profilesUnitAnnotation, profilesUnit)

			// Add required fields to the datasource
			stackField1, err := tt.ds.AddField(stackField1Name, api.Kind_String)
			require.NoError(t, err)

			stackField2, err := tt.ds.AddField(stackField2Name, api.Kind_String)
			require.NoError(t, err)

			valueField, err := tt.ds.AddField(valueFieldName, api.Kind_Int64)
			require.NoError(t, err)

			// Call PreStart to set up subscriptions
			err = tt.opInst.PreStart(tt.gadgetCtx)
			require.NoError(t, err)

			// Emit fake events using NewPacketArray
			dataArray, err := tt.ds.NewPacketArray()
			require.NoError(t, err)

			for i := 0; i < 3; i++ {
				data := dataArray.New()

				functions1 := fmt.Sprintf("function%d; function%d; function%d", i*5, i*10, i*20)
				err = stackField1.PutString(data, functions1)
				require.NoError(t, err)

				functions2 := fmt.Sprintf("function%d; function%d; function%d", i*6, i*12, i*24)
				err = stackField2.PutString(data, functions2)
				require.NoError(t, err)

				err = valueField.PutInt64(data, 42)
				require.NoError(t, err)

				dataArray.Append(data)
			}

			// Emit the data array
			err = tt.ds.EmitAndRelease(dataArray)
			require.NoError(t, err)

			// Check that Export was called
			require.Equal(t, 1, len(tt.mockClient.exportReq), "Export was not called on the mock client")

			exportReq := tt.mockClient.exportReq[0]
			profiles := exportReq.Profiles()
			require.Equal(t, 1, profiles.ResourceProfiles().Len(), "Expected one ResourceProfile")

			// Validate the profile structure
			rp := profiles.ResourceProfiles().At(0)

			// Validate resource attributes (service.name and service.version)
			resAttrs := rp.Resource().Attributes()
			serviceName, ok := resAttrs.Get("service.name")
			require.True(t, ok, "Expected service.name resource attribute")
			require.Equal(t, "inspektor-gadget", serviceName.Str(), "Expected service.name to be inspektor-gadget")

			serviceVersion, ok := resAttrs.Get("service.version")
			require.True(t, ok, "Expected service.version resource attribute")
			require.NotEmpty(t, serviceVersion.Str(), "Expected service.version to be non-empty")

			require.Equal(t, 1, rp.ScopeProfiles().Len(), "Expected one ScopeProfile")

			sp := rp.ScopeProfiles().At(0)
			require.Equal(t, "inspektor-gadget", sp.Scope().Name(), "Expected scope name to be inspektor-gadget")
			require.Equal(t, 1, sp.Profiles().Len(), "Expected one Profile")

			prof := sp.Profiles().At(0)
			require.Equal(t, 3, prof.Samples().Len(), "Expected three samples")

			// Check the sample
			sample := prof.Samples().At(0)
			require.Equal(t, 1, sample.Values().Len(), "Expected one value in sample")
			require.Equal(t, int64(42), sample.Values().At(0), "Bad sample value")

			// Check the stack
			dic := profiles.Dictionary()
			require.Equal(t, int32(1), sample.StackIndex(), "Expected stack index to be 1")

			for i := 0; i < 3; i++ {
				stack := dic.StackTable().At(i + 1)
				require.Equal(t, 6, stack.LocationIndices().Len(), "Bad number of locations in stack")

				// Check the functions in the stack
				expectedFunctions := []string{
					fmt.Sprintf("function%d", i*5),
					fmt.Sprintf("function%d", i*10),
					fmt.Sprintf("function%d", i*20),
					fmt.Sprintf("function%d", i*6),
					fmt.Sprintf("function%d", i*12),
					fmt.Sprintf("function%d", i*24),
				}
				for i, expectedFunc := range expectedFunctions {
					locationIdx := stack.LocationIndices().At(i)
					location := dic.LocationTable().At(int(locationIdx))
					require.Equal(t, 1, location.Lines().Len(), "Expected one line per location")

					functionIdx := location.Lines().At(0).FunctionIndex()
					function := dic.FunctionTable().At(int(functionIdx))

					nameStrIndex := function.NameStrindex()
					functionName := dic.StringTable().At(int(nameStrIndex))
					require.Equal(t, expectedFunc, functionName, "Expected function name to match")
				}
			}

			// Check sample type
			st := prof.SampleType()
			sampleTypeStr := dic.StringTable().At(int(st.TypeStrindex()))
			require.Equal(t, profilesType, sampleTypeStr, "Bad sample type")

			sampleUnitStr := dic.StringTable().At(int(st.UnitStrindex()))
			require.Equal(t, profilesUnit, sampleUnitStr, "Bad sample unit")

			// Check period type (used by Pyroscope to derive profile name)
			pt := prof.PeriodType()
			periodTypeStr := dic.StringTable().At(int(pt.TypeStrindex()))
			require.Equal(t, tc.expectedProfileName, periodTypeStr, "Bad period type")

			periodUnitStr := dic.StringTable().At(int(pt.UnitStrindex()))
			require.Equal(t, profilesUnit, periodUnitStr, "Bad period unit")

			require.Equal(t, int64(1), prof.Period(), "Bad period value")
		})
	}
}

func TestOtelProfilesSampleAttributeNames(t *testing.T) {
	t.Parallel()

	for _, sanitize := range []bool{false, true} {
		t.Run(fmt.Sprintf("sanitize=%t", sanitize), func(t *testing.T) {
			t.Parallel()
			testSampleAttributeNames(t, sanitize)
		})
	}
}

func testSampleAttributeNames(t *testing.T, sanitize bool) {
	tt := initTest(t)
	tt.opInst.sanitizeLabels = sanitize
	tt.ds.AddAnnotation(stackFieldsAnnotation, "stack")
	tt.ds.AddAnnotation(valueFieldAnnotation, "value")
	stackField, err := tt.ds.AddField("stack", api.Kind_String)
	require.NoError(t, err)
	valueField, err := tt.ds.AddField("value", api.Kind_Int64)
	require.NoError(t, err)

	attributes := []struct {
		fieldName string
		labelName string
		kind      api.Kind
		value     any
	}{
		{"k8s.namespace", "k8s_namespace", api.Kind_String, "ray-training"},
		{"k8s.podName", "k8s_podName", api.Kind_String, "gpu-worker"},
		{"proc.comm", "proc_comm", api.Kind_CString, "python"},
		{"runtime.container.name", "runtime_container_name", api.Kind_String, "worker"},
		{"already_normalized", "already_normalized", api.Kind_String, "unchanged"},
		{"proc.pid", "proc_pid", api.Kind_Int64, int64(42)},
		{"custom.enabled", "custom_enabled", api.Kind_Bool, true},
		{"custom.ratio", "custom_ratio", api.Kind_Float64, 1.5},
	}
	fields := make([]datasource.FieldAccessor, len(attributes))
	expected := make(map[string]any, len(attributes))
	for i, attr := range attributes {
		fields[i], err = tt.ds.AddField(attr.fieldName, attr.kind,
			datasource.WithAnnotations(map[string]string{sampleAttributeAnnotation: "true"}))
		require.NoError(t, err)
		if sanitize {
			expected[attr.labelName] = attr.value
		} else {
			expected[attr.fieldName] = attr.value
		}
	}
	_, err = tt.ds.AddField("k8s_podName", api.Kind_String)
	require.NoError(t, err)
	require.NoError(t, tt.opInst.PreStart(tt.gadgetCtx))

	dataArray, err := tt.ds.NewPacketArray()
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		data := dataArray.New()
		require.NoError(t, stackField.PutString(data, "allocate; train"))
		require.NoError(t, valueField.PutInt64(data, int64(i+1)))
		for j, attr := range attributes {
			switch val := attr.value.(type) {
			case string:
				require.NoError(t, fields[j].PutString(data, val))
			case int64:
				require.NoError(t, fields[j].PutInt64(data, val))
			case bool:
				require.NoError(t, fields[j].PutBool(data, val))
			case float64:
				require.NoError(t, fields[j].PutFloat64(data, val))
			default:
				t.Fatalf("unsupported test attribute value %T", val)
			}
		}
		dataArray.Append(data)
	}
	require.NoError(t, tt.ds.EmitAndRelease(dataArray))
	require.Len(t, tt.mockClient.exportReq, 1)

	wire, err := tt.mockClient.exportReq[0].MarshalProto()
	require.NoError(t, err)
	request := pprofileotlp.NewExportRequest()
	require.NoError(t, request.UnmarshalProto(wire))
	profiles := request.Profiles()
	dic := profiles.Dictionary()
	require.Equal(t, len(attributes)+1, dic.AttributeTable().Len())
	rp := profiles.ResourceProfiles().At(0)
	serviceName, ok := rp.Resource().Attributes().Get("service.name")
	require.True(t, ok)
	require.Equal(t, "inspektor-gadget", serviceName.Str())
	samples := rp.ScopeProfiles().At(0).Profiles().At(0).Samples()
	require.Equal(t, 3, samples.Len())
	for i := 0; i < samples.Len(); i++ {
		sample := samples.At(i)
		require.Equal(t, int64(i+1), sample.Values().At(0))
		require.Equal(t, len(attributes), sample.AttributeIndices().Len())
		actual := make(map[string]any, len(attributes))
		for j := 0; j < sample.AttributeIndices().Len(); j++ {
			attr := dic.AttributeTable().At(int(sample.AttributeIndices().At(j)))
			name := dic.StringTable().At(int(attr.KeyStrindex()))
			require.NotContains(t, actual, name)
			actual[name] = attr.Value().AsRaw()
		}
		require.Equal(t, expected, actual)
	}
}

func TestOtelProfilesSampleAttributeNameCollision(t *testing.T) {
	t.Parallel()

	for _, names := range [][]string{
		{"k8s.podName", "k8s_podName"},
		{"k8s_podName", "k8s.podName"},
		{"runtime.container.name", "runtime_container.name"},
	} {
		t.Run(names[0]+" and "+names[1], func(t *testing.T) {
			t.Parallel()

			tt := initTest(t)
			tt.opInst.sanitizeLabels = true
			tt.ds.AddAnnotation(stackFieldsAnnotation, "stack")
			tt.ds.AddAnnotation(valueFieldAnnotation, "value")
			_, err := tt.ds.AddField("stack", api.Kind_String)
			require.NoError(t, err)
			_, err = tt.ds.AddField("value", api.Kind_Int64)
			require.NoError(t, err)
			for _, name := range names {
				_, err := tt.ds.AddField(name, api.Kind_String,
					datasource.WithAnnotations(map[string]string{sampleAttributeAnnotation: "true"}))
				require.NoError(t, err)
			}

			err = tt.opInst.PreStart(tt.gadgetCtx)
			require.ErrorContains(t, err, "sample attribute name collision")
			require.ErrorContains(t, err, "test-datasource")
			for _, name := range names {
				require.ErrorContains(t, err, name)
			}
			require.Empty(t, tt.mockClient.exportReq)
		})
	}
}
