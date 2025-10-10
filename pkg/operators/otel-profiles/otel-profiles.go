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
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/collector/pdata/pprofile/pprofileotlp"
	semconv "go.opentelemetry.io/otel/semconv/v1.20.0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding/gzip"

	"github.com/inspektor-gadget/inspektor-gadget/internal/version"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/otel-profiles/orderedset"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	ParamOtelProfilesExporter = "otel-profiles-exporter"

	ExporterOTLPGRPC = "otlp-grpc"

	CompressionNone = "none"
	CompressionGZIP = "gzip"

	stackFieldAnnotation      = "profiles.stack-field"
	valueFieldAnnotation      = "profiles.value-field"
	sampleAttributeAnnotation = "profiles.sample-attribute"
)

var supportedExporters = []string{ExporterOTLPGRPC}

type profileConfig struct {
	Exporter    string `json:"exporter" yaml:"exporter"`
	Endpoint    string `json:"endpoint" yaml:"endpoint"`
	Insecure    bool   `json:"insecure" yaml:"insecure"`
	Compression string `json:"compression" yaml:"compression"`
}

type otelProfilesOperator struct {
	clients  map[string]pprofileotlp.GRPCClient
	callOpts []grpc.CallOption
}

func (o *otelProfilesOperator) Name() string {
	return "otel-profiles"
}

func (o *otelProfilesOperator) Init(params *params.Params) error {
	if config.Config == nil {
		return nil
	}

	o.clients = make(map[string]pprofileotlp.GRPCClient)
	o.callOpts = make([]grpc.CallOption, 0)

	configs := make(map[string]*profileConfig, 0)
	err := config.Config.UnmarshalKey("operator.otel-profiles.exporters", &configs)
	if err != nil {
		log.Warnf("failed to load operator.otel-profiles.exporters: %v", err)
	}

	for k, v := range configs {
		if v.Exporter != ExporterOTLPGRPC {
			return fmt.Errorf("unsupported log exporter %q; expected one of %s", v.Exporter,
				strings.Join(supportedExporters, ", "))
		}
		var options []grpc.DialOption

		if v.Insecure {
			options = append(options, grpc.WithTransportCredentials(insecure.NewCredentials()))
		}
		switch v.Compression {
		default:
			return fmt.Errorf("unsupported log compression %q", v.Compression)
		case "", CompressionNone:
		case CompressionGZIP:
			o.callOpts = append(o.callOpts, grpc.UseCompressor(gzip.Name))
		}

		conn, err := grpc.NewClient(v.Endpoint, options...)
		if err != nil {
			log.Errorf("creating gRPC connection to %q: %v", v.Endpoint, err)
			return fmt.Errorf("creating gRPC connection to %q: %w", v.Endpoint, err)
		}

		// TODO: there's not profiles processor?
		o.clients[k] = pprofileotlp.NewGRPCClient(conn)
	}

	return nil
}

func (o *otelProfilesOperator) GlobalParams() api.Params {
	return api.Params{}
}

func (o *otelProfilesOperator) InstanceParams() api.Params {
	return api.Params{
		&api.Param{
			Key:         ParamOtelProfilesExporter,
			Description: "Exporter to use for profiles exporting",
		},
	}
}

func (o *otelProfilesOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	if len(o.clients) == 0 {
		return nil, nil
	}

	mappings, err := apihelpers.GetStringValuesPerDataSource(instanceParamValues[ParamOtelProfilesExporter])
	if err != nil {
		return nil, fmt.Errorf("parsing name mappings: %w", err)
	}

	inst := &otelProfilesOperatorInstance{
		o:        o,
		mappings: mappings,
	}

	return inst, nil
}

func (o *otelProfilesOperator) Priority() int {
	return 9999
}

type otelProfilesOperatorInstance struct {
	o        *otelProfilesOperator
	mappings map[string]string
}

func (o *otelProfilesOperatorInstance) Name() string {
	return "otel-profiles"
}

func (o *otelProfilesOperatorInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	type function struct {
		nameIdx int32
	}

	type location struct {
		functionIdx int32
	}

	type attribute struct {
		keyIdx int32
		value  any
	}

	for _, ds := range gadgetCtx.GetDataSources() {
		exporterName, ok := o.mappings[ds.Name()]
		if !ok {
			exporterName, ok = o.mappings[""]
			if !ok {
				continue
			}
		}

		stackFieldAnn := ds.Annotations()[stackFieldAnnotation]
		if stackFieldAnn == "" {
			continue
		}
		valueFieldAnn := ds.Annotations()[valueFieldAnnotation]
		if valueFieldAnn == "" {
			continue
		}

		kStackField := ds.GetField(stackFieldAnn)
		if kStackField == nil {
			gadgetCtx.Logger().Warnf("skipping data source %s: field %q not found", ds.Name(), stackFieldAnn)
			continue
		}

		samplesField := ds.GetField(valueFieldAnn)
		if samplesField == nil {
			gadgetCtx.Logger().Warnf("skipping data source %s: field %q not found", ds.Name(), valueFieldAnn)
			continue
		}

		// TODO: These are attributes on the sample. Should we use the whole resource instead?
		attributeFields := make(map[string]datasource.FieldAccessor)

		for _, f := range ds.Fields() {
			if val, ok := f.Annotations[sampleAttributeAnnotation]; ok && val == "true" {
				attributeFields[f.FullName] = ds.GetField(f.FullName)
			}
		}

		err := ds.SubscribeArray(func(ds datasource.DataSource, da datasource.DataArray) error {
			profiles := pprofile.NewProfiles()

			dic := profiles.Dictionary()

			// by definition first one is empty
			dic.LinkTable().AppendEmpty()
			dic.MappingTable().AppendEmpty()
			dic.StackTable().AppendEmpty()
			dic.AttributeTable().AppendEmpty()

			stringSet := make(orderedset.OrderedSet[string], 64)
			stringSet.Add("")

			functionSet := make(orderedset.OrderedSet[function], 64)
			functionSet.Add(function{nameIdx: 0})

			locationSet := make(orderedset.OrderedSet[location], 64)
			locationSet.Add(location{functionIdx: 0})

			attributesSet := make(orderedset.OrderedSet[attribute], 64)
			attributesSet.Add(attribute{keyIdx: 0, value: nil})

			// resource profile
			rp := profiles.ResourceProfiles().AppendEmpty()
			// TODO: If we want to add the resource, we'll need to have something like:
			// rp.Resource().Attributes().PutStr("service.name", "example-service")
			rp.SetSchemaUrl(semconv.SchemaURL)

			// scope profile
			sp := rp.ScopeProfiles().AppendEmpty()
			sp.Scope().SetName("inspektor-gadget")
			sp.Scope().SetVersion(version.Version().String())

			// profile
			prof := sp.Profiles().AppendEmpty()

			st := prof.SampleType()
			// TODO: This should be configurable
			st.SetTypeStrindex(stringSet.Add("samples"))
			st.SetUnitStrindex(stringSet.Add("count"))

			attributeKeys := make(map[string]int32)
			for name := range attributeFields {
				keyIdx := stringSet.Add(name)
				attributeKeys[name] = keyIdx
			}

			stackIdx := int32(0)

			for i := 0; i < da.Len(); i++ {
				d := da.Get(i)

				kStack, err := kStackField.String(d)
				if err != nil {
					return err
				}

				samples, err := samplesField.Uint64(d)
				if err != nil {
					return err
				}

				// TODO: invert it?
				functions := strings.Split(kStack, "; ")

				sample := prof.Sample().AppendEmpty()
				sample.Values().Append(int64(samples))

				for attrName, field := range attributeFields {
					var val any

					switch field.Type() {
					case api.Kind_String, api.Kind_CString:
						val, err = field.String(d)
					case api.Kind_Bool:
						val, err = field.Bool(d)
					case api.Kind_Int64, api.Kind_Int32, api.Kind_Int16, api.Kind_Int8:
						val, err = field.Int64(d)
					case api.Kind_Uint64, api.Kind_Uint32, api.Kind_Uint16, api.Kind_Uint8:
						val, err = field.Uint64(d)
					case api.Kind_Float64, api.Kind_Float32:
						val, err = field.Float64(d)
					default:
						err = fmt.Errorf("unsupported attribute field type %v for field %q", field.Type(), field.FullName())

					}
					if err != nil {
						return err
					}

					index := attributesSet.Add(attribute{
						keyIdx: attributeKeys[attrName],
						value:  val,
					})

					sample.AttributeIndices().Append(index)
				}

				stack := dic.StackTable().AppendEmpty()

				for _, f := range functions {
					// add the function
					fIndex := functionSet.Add(function{nameIdx: int32(stringSet.Add(f))})

					// add the location
					loc := locationSet.Add(location{functionIdx: fIndex})

					stack.LocationIndices().Append(loc)
				}

				sample.SetStackIndex(stackIdx)
				stackIdx++
			}

			stringTable := dic.StringTable()
			stringTable.EnsureCapacity(len(stringSet))
			for _, val := range stringSet.ToSlice() {
				stringTable.Append(val)
			}

			functionTable := dic.FunctionTable()
			functionTable.EnsureCapacity(len(functionSet))
			for _, val := range functionSet.ToSlice() {
				fn := functionTable.AppendEmpty()
				fn.SetNameStrindex(val.nameIdx)
			}

			locationTable := dic.LocationTable()
			locationTable.EnsureCapacity(len(locationSet))
			for _, val := range locationSet.ToSlice() {
				location := locationTable.AppendEmpty()
				line := location.Line().AppendEmpty()
				line.SetFunctionIndex(val.functionIdx)
			}

			attributesTable := dic.AttributeTable()
			attributesTable.EnsureCapacity(len(attributesSet))
			for _, val := range attributesSet.ToSlice() {
				att := attributesTable.AppendEmpty()
				att.SetKeyStrindex(val.keyIdx)
				switch v := val.value.(type) {
				case string:
					att.Value().SetStr(v)
				case bool:
					att.Value().SetBool(v)
				case int64:
					att.Value().SetInt(v)
				case int32:
					att.Value().SetInt(int64(v))
				case int16:
					att.Value().SetInt(int64(v))
				case int8:
					att.Value().SetInt(int64(v))
				case int:
					att.Value().SetInt(int64(v))
				case uint64:
					att.Value().SetInt(int64(v))
				case uint32:
					att.Value().SetInt(int64(v))
				case uint16:
					att.Value().SetInt(int64(v))
				case uint8:
					att.Value().SetInt(int64(v))
				case uint:
					att.Value().SetInt(int64(v))
				case float64:
					att.Value().SetDouble(v)
				case float32:
					att.Value().SetDouble(float64(v))
				}
			}

			client, ok := o.o.clients[exporterName]
			if !ok {
				return fmt.Errorf("client not found: %q", exporterName)
			}

			req := pprofileotlp.NewExportRequestFromProfiles(profiles)

			res, err := client.Export(gadgetCtx.Context(), req, o.o.callOpts...)
			if err != nil {
				return err
			}

			if r := res.PartialSuccess().RejectedProfiles(); r > 0 {
				return fmt.Errorf("%d profiles rejected: %s", r, res.PartialSuccess().ErrorMessage())
			}

			return nil
		},
			101, // This needs to be lower than the ustack operator to be sure symbolization has already been done
		)
		if err != nil {
			return err
		}
	}

	return nil
}

func (o *otelProfilesOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (o *otelProfilesOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (o *otelProfilesOperatorInstance) Close(gadgetCtx operators.GadgetContext) error {
	return nil
}

var Operator = &otelProfilesOperator{}

func init() {
	operators.RegisterDataOperator(Operator)
}
