// Copyright 2024 The Inspektor Gadget authors
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

package otelmetrics

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
)

func TestMetricsInit(t *testing.T) {
	type test struct {
		name                      string
		metricsListenValue        string
		metricsListenAddressValue string
		expectedError             bool
	}

	tests := []test{
		{
			name:          "default params values",
			expectedError: false,
		},
		{
			name:               "enable listener with default address",
			metricsListenValue: "true",
			expectedError:      false,
		},
		{
			name:                      "enable listener at custom address",
			metricsListenValue:        "true",
			metricsListenAddressValue: "127.0.0.1:8080",
			expectedError:             false,
		},
		{
			name:                      "enable listener at invalid address",
			metricsListenValue:        "true",
			metricsListenAddressValue: "invalid",
			// TODO: Report error on Init
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &otelMetricsOperator{}
			globalParams := apihelpers.ToParamDescs(o.GlobalParams()).ToParams()

			if tt.metricsListenValue != "" {
				globalParams.Set(ParamOtelMetricsListen, tt.metricsListenValue)
			}
			if tt.metricsListenAddressValue != "" {
				globalParams.Set(ParamOtelMetricsListenAddress, tt.metricsListenAddressValue)
			}

			err := o.Init(globalParams)
			require.NoError(t, err)
			defer o.Close()

			if tt.metricsListenValue == "true" {
				// Wait for HTTP listener to start
				time.Sleep(500 * time.Millisecond)

				// Check if the listener is running at the expected address
				_, err := http.Get(fmt.Sprintf("http://%s/metrics", globalParams.Get(ParamOtelMetricsListenAddress)))
				if tt.expectedError {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}
			}
		})
	}
}

func TestMetricsCounterAndGauge(t *testing.T) {
	o := &otelMetricsOperator{skipListen: true}
	globalParams := apihelpers.ToParamDescs(o.GlobalParams()).ToParams()
	globalParams.Set(ParamOtelMetricsListen, "true")
	err := o.Init(globalParams)
	require.NoError(t, err)

	var ds datasource.DataSource
	var ctr datasource.FieldAccessor
	var gauge datasource.FieldAccessor

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()

	prepare := func(gadgetCtx operators.GadgetContext) error {
		var err error
		ds, err = gadgetCtx.RegisterDataSource(datasource.TypeSingle, "metrics")
		require.NoError(t, err)
		ds.AddAnnotation(AnnotationMetricsCollect, "true")

		ctr, err = ds.AddField("ctr", api.Kind_Uint32, datasource.WithAnnotations(map[string]string{
			AnnotationMetricsType: MetricTypeCounter,
		}))
		require.NoError(t, err)

		gauge, err = ds.AddField("gauge", api.Kind_Uint32, datasource.WithAnnotations(map[string]string{
			AnnotationMetricsType: MetricTypeGauge,
		}))
		require.NoError(t, err)
		return nil
	}
	produce := func(operators.GadgetContext) error {
		for i := range 10 {
			data, err := ds.NewPacketSingle()
			require.NoError(t, err)
			err = ctr.PutUint32(data, uint32(1))
			assert.NoError(t, err)
			err = gauge.PutUint32(data, uint32(i))
			assert.NoError(t, err)
			err = ds.EmitAndRelease(data)
			assert.NoError(t, err)
		}
		cancel()
		return nil
	}

	producer := simple.New("producer",
		simple.WithPriority(Priority-1),
		simple.OnInit(prepare),
		simple.OnStart(produce),
	)

	gadgetCtx := gadgetcontext.New(ctx, "", gadgetcontext.WithDataOperators(o, producer))

	err = gadgetCtx.Run(api.ParamValues{
		"operator.otel-metrics.otel-metrics-name": "metrics:metrics",
	})

	require.NoError(t, err)

	md := &metricdata.ResourceMetrics{}

	err = o.exporter.Collect(context.Background(), md)
	require.NoError(t, err)

	assert.NotEmpty(t, md.ScopeMetrics)
	for _, sm := range md.ScopeMetrics {
		assert.NotEmpty(t, sm)
		foundCtr := false
		foundGauge := false
		for _, m := range sm.Metrics {
			if m.Name == "ctr" {
				foundCtr = true
				data, ok := (m.Data).(metricdata.Sum[int64])
				assert.True(t, ok)
				assert.Equal(t, int64(10), data.DataPoints[0].Value)
			}
			if m.Name == "gauge" {
				foundGauge = true
				data, ok := (m.Data).(metricdata.Gauge[int64])
				assert.True(t, ok)
				assert.Equal(t, int64(9), data.DataPoints[0].Value)
			}
		}
		assert.True(t, foundCtr)
		assert.True(t, foundGauge)
	}
}

func TestMetricsHistogram(t *testing.T) {
	o := &otelMetricsOperator{skipListen: true}
	globalParams := apihelpers.ToParamDescs(o.GlobalParams()).ToParams()
	globalParams.Set(ParamOtelMetricsListen, "true")
	err := o.Init(globalParams)
	require.NoError(t, err)

	var ds datasource.DataSource
	var value datasource.FieldAccessor

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()

	expectedBuckets := []uint64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 3, 2, 3, 0}

	prepare := func(gadgetCtx operators.GadgetContext) error {
		var err error
		ds, err = gadgetCtx.RegisterDataSource(datasource.TypeSingle, "metrics")
		require.NoError(t, err)
		ds.AddAnnotation(AnnotationMetricsCollect, "true")
		value, err = ds.AddField("duration", api.Kind_Uint32, datasource.WithAnnotations(map[string]string{
			AnnotationMetricsType: MetricTypeHistogram,
		}))
		require.NoError(t, err)
		return nil
	}
	produce := func(operators.GadgetContext) error {
		for i := range 10 {
			data, err := ds.NewPacketSingle()
			require.NoError(t, err)
			err = value.PutUint32(data, uint32((i+1)*1000))
			assert.NoError(t, err)
			err = ds.EmitAndRelease(data)
			assert.NoError(t, err)
		}
		cancel()
		return nil
	}

	producer := simple.New("producer",
		simple.WithPriority(Priority-1),
		simple.OnInit(prepare),
		simple.OnStart(produce),
	)

	gadgetCtx := gadgetcontext.New(ctx, "", gadgetcontext.WithDataOperators(o, producer))

	err = gadgetCtx.Run(api.ParamValues{
		"operator.otel-metrics.otel-metrics-name": "metrics:metrics",
	})
	require.NoError(t, err)

	md := &metricdata.ResourceMetrics{}

	err = o.exporter.Collect(context.Background(), md)
	require.NoError(t, err)

	assert.NotEmpty(t, md.ScopeMetrics)
	for _, sm := range md.ScopeMetrics {
		assert.NotEmpty(t, sm)
		found := false
		for _, m := range sm.Metrics {
			if m.Name == "duration" {
				found = true
				data, ok := (m.Data).(metricdata.Histogram[int64])
				assert.True(t, ok)
				assert.Equal(t, 1, len(data.DataPoints))
				assert.Equal(t, len(expectedBuckets), len(data.DataPoints[0].BucketCounts))
				assert.Equal(t, expectedBuckets, data.DataPoints[0].BucketCounts)
			}
		}
		assert.True(t, found)
	}
}

// TestMetricsParamsAndAnnotations tests the following features:
//   - Print: This feature is requested by setting the AnnotationMetricsPrint
//     annotation to true. When requested, the tests verify the operator
//     creates and disable data sources as expected, and emits (or not) some data.
//   - Export: This feature is requested by setting the AnnotationMetricsPrint
//     annotation to true and the ParamOtelMetricsListen global parameter to
//     true. When requested, the tests verify the operator exports some data.
//
// The tests consider the following parameters/annotations/conditions:
//   - AnnotationMetricsPrint ds annotation (Print/NoPrint)
//   - AnnotationMetricsCollect ds annotation (Collect/NoCollect)
//   - ParamOtelMetricsListen global param (Export/NoExport)
//   - Where the operator is running gadgetcontext.WithAsRemoteCall(ClientSide/ServerSide)
//
// And, a few special cases:
//   - AnnotationMetricsType=MetricsTypeGauge field annotation (WithoutMetricsTypeHistogram)
//   - ParamOtelMetricsName instance param (WithoutMetricsName)
//
// Note these tests don't focus on the correctness of the data emitted or
// exported, but on the operator's behaviour. For the correctness of the data
// emitted or exported, see the other tests TestMetricsCounterAndGauge and
// TestMetricsHistogram.
func TestMetricsParamsAndAnnotations(t *testing.T) {
	const (
		producerPriority = Priority - 1
		consumerPriority = Priority + 1

		// With these values, we should catch at least one data packet
		testContextTimeout = 2 * time.Second
		testPrintInterval  = 1 * time.Second

		testDsName    = "test-metrics"
		testScopeName = "metrics-test-scope"

		testFieldName        = "myTestField"
		testFieldKind        = api.Kind_Uint32
		testFieldType        = MetricTypeHistogram
		testFieldDescription = "My test field description"
		testFieldUnit        = "ms"
		testFieldLongUnit    = "milliseconds"
	)

	var (
		fqParamMetricsName   = fmt.Sprintf("operator.%s.%s", name, ParamOtelMetricsName)
		fqParamPrintInterval = fmt.Sprintf("operator.%s.%s", name, ParamOtelMetricsPrintInterval)

		testMetricsName = fmt.Sprintf("%s:%s", testDsName, testScopeName)

		testExportedHelpEntry  = fmt.Sprintf("HELP %s_%s %s", testFieldName, testFieldLongUnit, testFieldDescription)
		testExportedTypeEntry  = fmt.Sprintf("TYPE %s_%s %s", testFieldName, testFieldLongUnit, testFieldType)
		testExportedScopeEntry = fmt.Sprintf("otel_scope_name=\"%s\"", testScopeName)

		testFieldAnnotations = map[string]string{
			AnnotationMetricsType:        testFieldType,
			AnnotationMetricsDescription: testFieldDescription,
			AnnotationMetricsUnit:        testFieldUnit,
			AnnotationMetricsBoundaries:  "0,1,2,3",
		}
	)

	type test struct {
		// Client or server side
		serverSide bool

		// Operator's global and instance parameters
		globalParamValues   map[string]string
		instanceParamValues api.ParamValues

		// Data and field annotations for the producer to create the data source
		dsAnnotations    map[string]string
		fieldAnnotations map[string]string

		// Expected behaviour to be verified by consumer or after the gadget run
		isRenderOutputExpected     bool
		areExportedMetricsExpected bool
	}

	tests := map[string]test{
		// Only exporting metrics on client side: ok
		"ClientSide-NoPrint-Collect-Export": {
			serverSide: false,
			globalParamValues: map[string]string{
				ParamOtelMetricsListen: "true",
			},
			instanceParamValues: api.ParamValues{
				fqParamMetricsName:   testMetricsName,
				fqParamPrintInterval: testPrintInterval.String(),
			},
			dsAnnotations: map[string]string{
				AnnotationMetricsCollect: "true",
				AnnotationMetricsPrint:   "false",
			},
			fieldAnnotations:           testFieldAnnotations,
			isRenderOutputExpected:     false,
			areExportedMetricsExpected: true,
		},
		// Trying to export metrics on client side without collect: ko - collect is required to export
		"ClientSide-NoPrint-NoCollect-Export": {
			serverSide: false,
			globalParamValues: map[string]string{
				ParamOtelMetricsListen: "true",
			},
			instanceParamValues: api.ParamValues{
				fqParamMetricsName:   testMetricsName,
				fqParamPrintInterval: testPrintInterval.String(),
			},
			dsAnnotations: map[string]string{
				AnnotationMetricsCollect: "false",
				AnnotationMetricsPrint:   "false",
			},
			fieldAnnotations:           testFieldAnnotations,
			isRenderOutputExpected:     false,
			areExportedMetricsExpected: false,
		},
		// Only printing metrics on client side: ok
		"ClientSide-Print-NoCollect-NoExport": {
			serverSide: false,
			globalParamValues: map[string]string{
				ParamOtelMetricsListen: "false",
			},
			instanceParamValues: api.ParamValues{
				fqParamMetricsName:   testMetricsName,
				fqParamPrintInterval: testPrintInterval.String(),
			},
			dsAnnotations: map[string]string{
				AnnotationMetricsCollect: "false",
				AnnotationMetricsPrint:   "true",
			},
			fieldAnnotations:           testFieldAnnotations,
			isRenderOutputExpected:     true,
			areExportedMetricsExpected: false,
		},
		// Exporting and printing metrics on client side: ok
		"ClientSide-Print-Collect-Export": {
			serverSide: false,
			globalParamValues: map[string]string{
				ParamOtelMetricsListen: "true",
			},
			instanceParamValues: api.ParamValues{
				fqParamMetricsName:   testMetricsName,
				fqParamPrintInterval: testPrintInterval.String(),
			},
			dsAnnotations: map[string]string{
				AnnotationMetricsCollect: "true",
				AnnotationMetricsPrint:   "true",
			},
			fieldAnnotations:           testFieldAnnotations,
			isRenderOutputExpected:     true,
			areExportedMetricsExpected: true,
		},
		// Setting print + collect on client side: ko - Collect is ignored if export is disabled
		// TBD: Shouldn't we inform users about this?
		"ClientSide-Print-Collect-NoExport": {
			serverSide: false,
			globalParamValues: map[string]string{
				ParamOtelMetricsListen: "false",
			},
			instanceParamValues: api.ParamValues{
				fqParamMetricsName:   testMetricsName,
				fqParamPrintInterval: testPrintInterval.String(),
			},
			dsAnnotations: map[string]string{
				AnnotationMetricsCollect: "true",
				AnnotationMetricsPrint:   "true",
			},
			fieldAnnotations:           testFieldAnnotations,
			isRenderOutputExpected:     true,
			areExportedMetricsExpected: false,
		},
		// Do noting on client side: ok
		"ClientSide-NoPrint-NoCollect-NoExport": {
			serverSide: false,
			globalParamValues: map[string]string{
				ParamOtelMetricsListen: "false",
			},
			instanceParamValues: api.ParamValues{
				fqParamMetricsName:   testMetricsName,
				fqParamPrintInterval: testPrintInterval.String(),
			},
			dsAnnotations: map[string]string{
				AnnotationMetricsCollect: "false",
				AnnotationMetricsPrint:   "false",
			},
			fieldAnnotations:           testFieldAnnotations,
			isRenderOutputExpected:     false,
			areExportedMetricsExpected: false,
		},
		// Collect does nothing without global export on client side: ko
		// TBD: Shouldn't we inform users about this?
		"ClientSide-NoPrint-Collect-NoExport": {
			serverSide: false,
			globalParamValues: map[string]string{
				ParamOtelMetricsListen: "false",
			},
			instanceParamValues: api.ParamValues{
				fqParamMetricsName:   testMetricsName,
				fqParamPrintInterval: testPrintInterval.String(),
			},
			dsAnnotations: map[string]string{
				AnnotationMetricsCollect: "true",
				AnnotationMetricsPrint:   "false",
			},
			fieldAnnotations:           testFieldAnnotations,
			isRenderOutputExpected:     false,
			areExportedMetricsExpected: false,
		},
		// Trying to export and print metrics on client side without collect: ok but should be ko
		// TBD: When print is set, collect is not required to export metrics on
		// client side. I suggest making collect mandatory for exporting
		"ClientSide-Print-NoCollect-Export": {
			serverSide: false,
			globalParamValues: map[string]string{
				ParamOtelMetricsListen: "true",
			},
			instanceParamValues: api.ParamValues{
				fqParamMetricsName:   testMetricsName,
				fqParamPrintInterval: testPrintInterval.String(),
			},
			dsAnnotations: map[string]string{
				AnnotationMetricsCollect: "false",
				AnnotationMetricsPrint:   "true",
			},
			fieldAnnotations:           testFieldAnnotations,
			isRenderOutputExpected:     true,
			areExportedMetricsExpected: true,
		},
		// Trying to export metrics on server side without collect: ko - Print
		// is ignored on server side so, collect is required to export metrics
		"ServerSide-Print-NoCollect-Export": {
			serverSide: true,
			globalParamValues: map[string]string{
				ParamOtelMetricsListen: "true",
			},
			instanceParamValues: api.ParamValues{
				fqParamMetricsName:   testMetricsName,
				fqParamPrintInterval: testPrintInterval.String(),
			},
			dsAnnotations: map[string]string{
				AnnotationMetricsCollect: "false",
				AnnotationMetricsPrint:   "true",
			},
			fieldAnnotations:           testFieldAnnotations,
			isRenderOutputExpected:     false,
			areExportedMetricsExpected: false,
		},
		// Trying to export metrics on server side without collect: ko - Note
		// print is ignored on server side
		"ServerSide-NoPrint-NoCollect-Export": {
			serverSide: true,
			globalParamValues: map[string]string{
				ParamOtelMetricsListen: "true",
			},
			instanceParamValues: api.ParamValues{
				fqParamMetricsName:   testMetricsName,
				fqParamPrintInterval: testPrintInterval.String(),
			},
			dsAnnotations: map[string]string{
				AnnotationMetricsCollect: "false",
				AnnotationMetricsPrint:   "false",
			},
			fieldAnnotations:           testFieldAnnotations,
			isRenderOutputExpected:     false,
			areExportedMetricsExpected: false,
		},
		// Exporting metrics on server side: ok - Note print is ignored on
		// server side
		"ServerSide-Print-Collect-Export": {
			serverSide: true,
			globalParamValues: map[string]string{
				ParamOtelMetricsListen: "true",
			},
			instanceParamValues: api.ParamValues{
				fqParamMetricsName:   testMetricsName,
				fqParamPrintInterval: testPrintInterval.String(),
			},
			dsAnnotations: map[string]string{
				AnnotationMetricsCollect: "true",
				AnnotationMetricsPrint:   "true",
			},
			fieldAnnotations:           testFieldAnnotations,
			isRenderOutputExpected:     false,
			areExportedMetricsExpected: true,
		},
		// Exporting metrics on server side: ok
		"ServerSide-NoPrint-Collect-Export": {
			serverSide: true,
			globalParamValues: map[string]string{
				ParamOtelMetricsListen: "true",
			},
			instanceParamValues: api.ParamValues{
				fqParamMetricsName:   testMetricsName,
				fqParamPrintInterval: testPrintInterval.String(),
			},
			dsAnnotations: map[string]string{
				AnnotationMetricsCollect: "true",
				AnnotationMetricsPrint:   "false",
			},
			fieldAnnotations:           testFieldAnnotations,
			isRenderOutputExpected:     false,
			areExportedMetricsExpected: true,
		},
		// Printing metrics on server side: ko - Print is ignored on server side
		"ServerSide-Print-NoCollect-NoExport": {
			serverSide: true,
			globalParamValues: map[string]string{
				ParamOtelMetricsListen: "false",
			},
			instanceParamValues: api.ParamValues{
				fqParamMetricsName:   testMetricsName,
				fqParamPrintInterval: testPrintInterval.String(),
			},
			dsAnnotations: map[string]string{
				AnnotationMetricsCollect: "false",
				AnnotationMetricsPrint:   "true",
			},
			fieldAnnotations:           testFieldAnnotations,
			isRenderOutputExpected:     false,
			areExportedMetricsExpected: false,
		},
		// Setting print + collect on server side: ko - Both print adn collect are ignored
		// TBD: Shouldn't we inform users about this?
		"ServerSide-Print-Collect-NoExport": {
			serverSide: true,
			globalParamValues: map[string]string{
				ParamOtelMetricsListen: "false",
			},
			instanceParamValues: api.ParamValues{
				fqParamMetricsName:   testMetricsName,
				fqParamPrintInterval: testPrintInterval.String(),
			},
			dsAnnotations: map[string]string{
				AnnotationMetricsCollect: "true",
				AnnotationMetricsPrint:   "true",
			},
			fieldAnnotations:           testFieldAnnotations,
			isRenderOutputExpected:     false,
			areExportedMetricsExpected: false,
		},
		// Do noting on server side: ok
		"ServerSide-NoPrint-NoCollect-NoExport": {
			serverSide: true,
			globalParamValues: map[string]string{
				ParamOtelMetricsListen: "false",
			},
			instanceParamValues: api.ParamValues{
				fqParamMetricsName:   testMetricsName,
				fqParamPrintInterval: testPrintInterval.String(),
			},
			dsAnnotations: map[string]string{
				AnnotationMetricsCollect: "false",
				AnnotationMetricsPrint:   "false",
			},
			fieldAnnotations:           testFieldAnnotations,
			isRenderOutputExpected:     false,
			areExportedMetricsExpected: false,
		},
		// Collect does nothing without export on server side: ko
		// TBD: Shouldn't we inform users about this?
		"ServerSide-NoPrint-Collect-NoExport": {
			serverSide: true,
			globalParamValues: map[string]string{
				ParamOtelMetricsListen: "false",
			},
			instanceParamValues: api.ParamValues{
				fqParamMetricsName:   testMetricsName,
				fqParamPrintInterval: testPrintInterval.String(),
			},
			dsAnnotations: map[string]string{
				AnnotationMetricsCollect: "true",
				AnnotationMetricsPrint:   "false",
			},
			fieldAnnotations:           testFieldAnnotations,
			isRenderOutputExpected:     false,
			areExportedMetricsExpected: false,
		},

		// Special cases: playing with metrics type and metrics-name

		// Exporting metrics on server side: Metrics name is required to export
		// TBD: Shouldn't we inform users about this?
		"ServerSide-NoPrint-Collect-Export-WithoutMetricsName": {
			serverSide: true,
			globalParamValues: map[string]string{
				ParamOtelMetricsListen: "true",
			},
			instanceParamValues: api.ParamValues{
				fqParamPrintInterval: testPrintInterval.String(),
			},
			dsAnnotations: map[string]string{
				AnnotationMetricsCollect: "true",
				AnnotationMetricsPrint:   "false",
			},
			fieldAnnotations:           testFieldAnnotations,
			isRenderOutputExpected:     false,
			areExportedMetricsExpected: false,
		},
		// Exporting metrics on client side: Metrics name is required to export
		// TBD: Shouldn't we inform users about this?
		"ClientSide-NoPrint-Collect-Export-WithoutMetricsName": {
			serverSide: false,
			globalParamValues: map[string]string{
				ParamOtelMetricsListen: "true",
			},
			instanceParamValues: api.ParamValues{
				fqParamPrintInterval: testPrintInterval.String(),
			},
			dsAnnotations: map[string]string{
				AnnotationMetricsCollect: "true",
				AnnotationMetricsPrint:   "false",
			},
			fieldAnnotations:           testFieldAnnotations,
			isRenderOutputExpected:     false,
			areExportedMetricsExpected: false,
		},
		// Printing metrics on client side: if field type is different from
		// histogram, new datasource is created but no data is emitted. Export
		// is expected to work.
		// TBD: What to do when the field type is not supported?
		// "ClientSide-Print-Collect-Export-WithoutMetricsTypeHistogram": {
		// 	serverSide: false,
		// 	globalParamValues: map[string]string{
		// 		ParamOtelMetricsListen: "true",
		// 	},
		// 	instanceParamValues: api.ParamValues{
		// 		fqParamMetricsName:   testMetricsName,
		// 		fqParamPrintInterval: testPrintInterval.String(),
		// 	},
		// 	dsAnnotations: map[string]string{
		// 		AnnotationMetricsCollect: "true",
		// 		AnnotationMetricsPrint:   "true",
		// 	},
		// 	fieldAnnotations: map[string]string{
		// 		AnnotationMetricsType:        MetricTypeGauge,
		// 		AnnotationMetricsDescription: testFieldDescription,
		// 		AnnotationMetricsUnit:        testFieldUnit,
		// 	},
		// 	isRenderOutputExpected:     false,
		// 	areExportedMetricsExpected: true,
		// },
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			otelMetricsOp := &otelMetricsOperator{}
			globalParams := apihelpers.ToParamDescs(otelMetricsOp.GlobalParams()).ToParams()
			for k, v := range tt.globalParamValues {
				globalParams.Set(k, v)
			}
			err := otelMetricsOp.Init(globalParams)
			require.NoError(t, err)
			defer otelMetricsOp.Close()

			var ds datasource.DataSource
			var field datasource.FieldAccessor
			initProducer := func(gadgetCtx operators.GadgetContext) error {
				var err error

				ds, err = gadgetCtx.RegisterDataSource(datasource.TypeSingle, testDsName)
				require.NoError(t, err)
				for k, v := range tt.dsAnnotations {
					ds.AddAnnotation(k, v)
				}

				field, err = ds.AddField(testFieldName, testFieldKind)
				require.NoError(t, err)
				for k, v := range tt.fieldAnnotations {
					field.AddAnnotation(k, v)
				}
				return nil
			}
			startProducer := func(operators.GadgetContext) error {
				for i := range 4 {
					data, err := ds.NewPacketSingle()
					require.NoError(t, err)
					err = field.PutUint32(data, uint32(i))
					require.NoError(t, err)
					err = ds.EmitAndRelease(data)
					require.NoError(t, err)
				}
				return nil
			}

			counterRenderedDsOutputs := 0
			counterOriginalDsOutputs := 0
			preStartConsumer := func(gadgetCtx operators.GadgetContext) error {
				originalDS, originalDsOk := gadgetCtx.GetDataSources()[testDsName]
				renderedDS, renderedDsOk := gadgetCtx.GetDataSources()[fmt.Sprintf("%s-%s", testDsName, PrintDataSourceSuffix)]

				if tt.isRenderOutputExpected {
					require.True(t, renderedDsOk)
					require.False(t, originalDsOk)

					// Verify ds has the expected CLI annotations
					renderedDsAnnotations := renderedDS.Annotations()
					for k, v := range renderedDsCliAnnotations {
						assert.Equal(t, v, renderedDsAnnotations[k])
					}

					// Verify ds has also the original annotations
					for k, v := range tt.dsAnnotations {
						assert.Equal(t, v, renderedDsAnnotations[k])
					}

					// Verify ds has the expected fields:
					// This information is hardcoded in the operator and should never change
					renderedFields := renderedDS.Fields()
					require.Len(t, renderedFields, 1)
					require.Equal(t, PrintFieldName, renderedFields[0].Name)
					require.Equal(t, api.Kind_String, renderedFields[0].Kind)

					// Verify ds emits the expected number of data packets
					renderedDS.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
						counterRenderedDsOutputs++
						return nil
					}, consumerPriority)
				} else {
					require.False(t, renderedDsOk)
					require.True(t, originalDsOk)

					// Verify there were no changes to the ds's annotations
					require.True(t, originalDsOk)
					originalDSAnnotations := originalDS.Annotations()
					for k, v := range tt.dsAnnotations {
						assert.Equal(t, v, originalDSAnnotations[k])
					}

					// Verify there were no changes to the ds's fields
					originalFields := originalDS.Fields()
					require.Len(t, originalFields, 1)
					require.Equal(t, testFieldName, originalFields[0].Name)
					require.Equal(t, testFieldKind, originalFields[0].Kind)

					// Verify ds emits the expected number of data packets
					originalDS.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
						counterOriginalDsOutputs++
						return nil
					}, consumerPriority)
				}

				return nil
			}
			postStopConsumer := func(operators.GadgetContext) error {
				// Verify datasources emitted, at least, some data
				if tt.isRenderOutputExpected {
					require.Greater(t, counterRenderedDsOutputs, 0)
				} else {
					require.Greater(t, counterOriginalDsOutputs, 0)
				}
				return nil
			}

			producerOp := simple.New("producer",
				// Operator running before the otel metrics operator and
				// registering a datasource, e.g., the eBPF Operator
				simple.WithPriority(producerPriority),
				simple.OnInit(initProducer),
				simple.OnStart(startProducer),
			)

			consumerOp := simple.New("consumer",
				// Operator running after the otel metrics operator and
				// consuming the generated data, e.g., the CLI Operator
				simple.WithPriority(consumerPriority),
				simple.OnPreStart(preStartConsumer),
				simple.OnPostStop(postStopConsumer),
			)

			// l := logger.DefaultLogger()
			// l.SetLevel(logger.DebugLevel)

			gadgetCtx := gadgetcontext.New(
				context.Background(),
				"",
				gadgetcontext.WithDataOperators(otelMetricsOp, producerOp, consumerOp),
				gadgetcontext.WithAsRemoteCall(tt.serverSide),
				gadgetcontext.WithTimeout(testContextTimeout),
				// gadgetcontext.WithLogger(l),
			)
			defer gadgetCtx.Cancel()

			err = gadgetCtx.Run(tt.instanceParamValues)
			require.NoError(t, err, "error running the gadget context %v", err)

			// Exporter is at the global operator level, so we can verify the
			// exported metrics even after the gadget stops
			if tt.areExportedMetricsExpected {
				resp, err := http.Get(fmt.Sprintf("http://%s/metrics", globalParams.Get(ParamOtelMetricsListenAddress)))
				require.NoError(t, err)
				defer resp.Body.Close()

				require.Equal(t, http.StatusOK, resp.StatusCode)

				bodyBytes, err := io.ReadAll(resp.Body)
				require.NoError(t, err)

				require.Contains(t, string(bodyBytes), testExportedHelpEntry)
				require.Contains(t, string(bodyBytes), testExportedTypeEntry)
				require.Contains(t, string(bodyBytes), testExportedScopeEntry)
			}
		})
	}
}
