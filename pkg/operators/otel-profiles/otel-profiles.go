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

// Package otelprofiles operator exports profiling data in OpenTelemetry format.
// This is still experimental as the support for otel profiles is being
// developed: https://opentelemetry.io/blog/2024/state-profiling/
package otelprofiles

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/collector/pdata/pprofile/pprofileotlp"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
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
	opName = "otel-profiles"

	ParamOtelProfilesExporter = "otel-profiles-exporter"

	ExporterOTLPGRPC = "otlp-grpc"

	CompressionNone = "none"
	CompressionGZIP = "gzip"

	stackFieldsAnnotation     = "profiles.stack-fields"
	valueFieldAnnotation      = "profiles.value-field"
	sampleAttributeAnnotation = "profiles.sample-attribute"
	profilesTypeAnnotation    = "profiles.type"
	profilesUnitAnnotation    = "profiles.unit"

	tagGroupOtelProfiles = "group:OpenTelemetry Profiles"

	opPriority = 9999

	// This needs to be lower than the ustack operator to be sure symbolization has already been done
	subscribePriority = 101
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
	callOpts map[string][]grpc.CallOption
}

func (o *otelProfilesOperator) Name() string {
	return opName
}

func (o *otelProfilesOperator) Init(params *params.Params) error {
	if config.Config == nil {
		return nil
	}

	o.clients = make(map[string]pprofileotlp.GRPCClient)
	o.callOpts = make(map[string][]grpc.CallOption)

	configs := make(map[string]*profileConfig)
	err := config.Config.UnmarshalKey("operator.otel-profiles.exporters", &configs)
	if err != nil {
		log.Warnf("failed to load operator.otel-profiles.exporters: %v", err)
	}

	for k, v := range configs {
		if v.Exporter != ExporterOTLPGRPC {
			return fmt.Errorf("unsupported profile exporter %q; expected one of %s", v.Exporter,
				strings.Join(supportedExporters, ", "))
		}
		var options []grpc.DialOption

		if v.Insecure {
			options = append(options, grpc.WithTransportCredentials(insecure.NewCredentials()))
		}
		switch v.Compression {
		default:
			return fmt.Errorf("unsupported profile compression %q", v.Compression)
		case "", CompressionNone:
		case CompressionGZIP:
			o.callOpts[k] = append(o.callOpts[k], grpc.UseCompressor(gzip.Name))
		}

		conn, err := grpc.NewClient(v.Endpoint, options...)
		if err != nil {
			log.Errorf("creating gRPC connection to %q: %v", v.Endpoint, err)
			return fmt.Errorf("creating gRPC connection to %q: %w", v.Endpoint, err)
		}

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
			Title:       "Profiles Exporter",
			Description: "Exporter to use for profiles exporting",
			Tags:        []string{tagGroupOtelProfiles},
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
	return opPriority
}

type otelProfilesOperatorInstance struct {
	o        *otelProfilesOperator
	mappings map[string]string
}

func (o *otelProfilesOperatorInstance) Name() string {
	return opName
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

		stackFieldsAnn := ds.Annotations()[stackFieldsAnnotation]
		if stackFieldsAnn == "" {
			continue
		}
		valueFieldAnn := ds.Annotations()[valueFieldAnnotation]
		if valueFieldAnn == "" {
			continue
		}

		var stackFields []datasource.FieldAccessor
		stackFieldsStr := strings.Split(stackFieldsAnn, ",")
		for _, f := range stackFieldsStr {
			if f == "" {
				continue
			}
			field := ds.GetField(f)
			if field == nil {
				gadgetCtx.Logger().Warnf("skipping data source %s: field %q not found", ds.Name(), f)
				continue
			}
			stackFields = append(stackFields, field)
		}
		if len(stackFields) == 0 {
			gadgetCtx.Logger().Warnf("skipping data source %s: no valid stack field found", ds.Name())
			continue
		}

		valueField := ds.GetField(valueFieldAnn)
		if valueField == nil {
			gadgetCtx.Logger().Warnf("skipping data source %s: field %q not found", ds.Name(), valueFieldAnn)
			continue
		}

		var valueFn func(data datasource.Data) int64

		switch valueField.Type() {
		default:
			gadgetCtx.Logger().Warnf("skipping data source %s: value field %q has unsupported type %v", ds.Name(), valueFieldAnn, valueField.Type())
			continue
		case api.Kind_Int64, api.Kind_Int32, api.Kind_Int16, api.Kind_Int8,
			api.Kind_Uint64, api.Kind_Uint32, api.Kind_Uint16, api.Kind_Uint8:
			// no error can happen
			valueFn, _ = datasource.AsInt64(valueField)
		}

		attributesGetter := make(map[string]func(data datasource.Data) (any, error))
		for _, f := range ds.Fields() {
			if val, ok := f.Annotations[sampleAttributeAnnotation]; ok && val == "true" {
				field := ds.GetField(f.FullName)

				getter := func(data datasource.Data) (any, error) {
					switch field.Type() {
					case api.Kind_String, api.Kind_CString:
						return field.String(data)
					case api.Kind_Bool:
						return field.Bool(data)
					case api.Kind_Int64:
						return field.Int64(data)
					case api.Kind_Int32:
						return field.Int32(data)
					case api.Kind_Int16:
						return field.Int16(data)
					case api.Kind_Int8:
						return field.Int8(data)
					case api.Kind_Uint64:
						return field.Uint64(data)
					case api.Kind_Uint32:
						return field.Uint32(data)
					case api.Kind_Uint16:
						return field.Uint16(data)
					case api.Kind_Uint8:
						return field.Uint8(data)
					case api.Kind_Float64:
						return field.Float64(data)
					case api.Kind_Float32:
						return field.Float32(data)
					default:
						return nil, fmt.Errorf("unsupported attribute field type %v for field %q", field.Type(), field.FullName())
					}
				}

				attributesGetter[f.FullName] = getter
			}
		}

		profilesType := "samples"
		if val, ok := ds.Annotations()[profilesTypeAnnotation]; ok && val != "" {
			profilesType = val
		}

		profilesUnit := "count"
		if val, ok := ds.Annotations()[profilesUnitAnnotation]; ok && val != "" {
			profilesUnit = val
		}

		client, ok := o.o.clients[exporterName]
		if !ok {
			return fmt.Errorf("client not found: %q", exporterName)
		}
		callOpts := o.o.callOpts[exporterName]

		err := ds.SubscribeArray(func(ds datasource.DataSource, da datasource.DataArray) error {
			profiles := pprofile.NewProfiles()

			dic := profiles.Dictionary()

			// by definition first one is empty
			dic.LinkTable().AppendEmpty()
			dic.MappingTable().AppendEmpty()
			dic.StackTable().AppendEmpty()

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
			rp.SetSchemaUrl(semconv.SchemaURL)

			// scope profile
			sp := rp.ScopeProfiles().AppendEmpty()
			sp.Scope().SetName("inspektor-gadget")
			sp.Scope().SetVersion(version.Version().String())

			// profile
			prof := sp.Profiles().AppendEmpty()

			st := prof.SampleType()
			st.SetTypeStrindex(stringSet.Add(profilesType))
			st.SetUnitStrindex(stringSet.Add(profilesUnit))

			attributeKeys := make(map[string]int32)
			for name := range attributesGetter {
				keyIdx := stringSet.Add(name)
				attributeKeys[name] = keyIdx
			}

			stackIdx := int32(1)

			for i := 0; i < da.Len(); i++ {
				d := da.Get(i)

				var functions []string

				for _, field := range stackFields {
					stackStr, err := field.String(d)
					if err != nil {
						return err
					}

					// TODO: ideally the stack would be an array of objects with
					// fields like name, addres, line number, etc. but we need
					// https://github.com/inspektor-gadget/inspektor-gadget/issues/3032
					// first
					functions = append(functions, strings.Split(stackStr, "; ")...)
				}

				value := valueFn(d)
				sample := prof.Sample().AppendEmpty()
				sample.Values().Append(value)

				for attrName, getter := range attributesGetter {
					val, err := getter(d)
					if err != nil {
						return fmt.Errorf("getting attribute %q: %w", attrName, err)
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

			req := pprofileotlp.NewExportRequestFromProfiles(profiles)

			res, err := client.Export(gadgetCtx.Context(), req, callOpts...)
			if err != nil {
				return err
			}

			if r := res.PartialSuccess().RejectedProfiles(); r > 0 {
				return fmt.Errorf("%d profiles rejected: %s", r, res.PartialSuccess().ErrorMessage())
			}

			return nil
		}, subscribePriority)
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
