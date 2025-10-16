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
)

var supportedExporters = []string{ExporterOTLPGRPC}

type profileConfig struct {
	Exporter    string `json:"exporter" yaml:"exporter"`
	Endpoint    string `json:"endpoint" yaml:"endpoint"`
	Insecure    bool   `json:"insecure" yaml:"insecure"`
	Compression string `json:"compression" yaml:"compression"`
}

type otelProfilesOperator struct {
	clients map[string]pprofileotlp.GRPCClient
}

func (o *otelProfilesOperator) Name() string {
	return "otel-profiles"
}

func (o *otelProfilesOperator) Init(params *params.Params) error {
	if config.Config == nil {
		return nil
	}

	o.clients = make(map[string]pprofileotlp.GRPCClient)

	configs := make(map[string]*profileConfig, 0)
	log.Infof("loading profile exporters")
	err := config.Config.UnmarshalKey("operator.otel-profiles.exporters", &configs)
	if err != nil {
		log.Warnf("failed to load operator.otel-profiles.exporters: %v", err)
	}

	log.Infof("loaded %d profile exporters", len(configs))

	for k, v := range configs {
		log.Infof("loading profile exporter %q", k)

		if v.Exporter != ExporterOTLPGRPC {
			return fmt.Errorf("unsupported log exporter %q; expected one of %s", v.Exporter,
				strings.Join(supportedExporters, ", "))
		}
		var options []grpc.DialOption
		var callOpts []grpc.CallOption

		//options = append(options, otlploggrpc.WithEndpoint(v.Endpoint))
		if v.Insecure {
			options = append(options, grpc.WithTransportCredentials(insecure.NewCredentials()))
		}
		switch v.Compression {
		default:
			return fmt.Errorf("unsupported log compression %q", v.Compression)
		case "", CompressionNone:
		case CompressionGZIP:
			callOpts = append(callOpts, grpc.UseCompressor(gzip.Name))
		}

		conn, err := grpc.NewClient(v.Endpoint, options...)
		if err != nil {
			log.Errorf("creating gRPC connection to %q: %v", v.Endpoint, err)
			return fmt.Errorf("creating gRPC connection to %q: %w", v.Endpoint, err)
		}

		// TODO: there's not profiles processor?
		o.clients[k] = pprofileotlp.NewGRPCClient(conn)
		log.Infof("> log exporter %q with endpoint %q loaded", k, v.Endpoint)
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
	// subscribe to data sources

	// TODO: move to init to understand if an instance needs to be created?
	for _, ds := range gadgetCtx.GetDataSources() {
		exporterName, ok := o.mappings[ds.Name()]
		if !ok {
			exporterName, ok = o.mappings[""]
			if !ok {
				continue
			}
		}

		gadgetCtx.Logger().Infof("Trying to data source %s", ds.Name())

		stackFieldAnn := ds.Annotations()["profiles.stack-field"]
		if stackFieldAnn == "" {
			gadgetCtx.Logger().Infof("skipping data source %s: no profiles.stack-field annotation", ds.Name())
			continue
		}
		valueFieldAnn := ds.Annotations()["profiles.value-field"]
		if valueFieldAnn == "" {
			gadgetCtx.Logger().Infof("skipping data source %s: no profiles.value-field annotation", ds.Name())
			continue
		}

		// TODO: an annotation instead

		kStackField := ds.GetField(stackFieldAnn)
		if kStackField == nil {
			continue
		}

		samplesField := ds.GetField(valueFieldAnn)
		if samplesField == nil {
			continue
		}

		gadgetCtx.Logger().Infof("Subscribing to data source %s", ds.Name())

		err := ds.SubscribeArray(func(ds datasource.DataSource, da datasource.DataArray) error {
			profiles := pprofile.NewProfiles()

			dic := profiles.Dictionary()

			// by definition first one is empty
			dic.LinkTable().AppendEmpty()
			dic.MappingTable().AppendEmpty()
			dic.StackTable().AppendEmpty()
			dic.AttributeTable().AppendEmpty()
			//dic.LocationTable().AppendEmpty()
			//dic.FunctionTable().AppendEmpty()

			stringSet := make(orderedset.OrderedSet[string], 64)
			stringSet.Add("")

			type function struct {
				nameIdx int32
			}

			type location struct {
				functionIdx int32
			}

			functionSet := make(orderedset.OrderedSet[function], 64)
			functionSet.Add(function{nameIdx: 0})

			locationSet := make(orderedset.OrderedSet[location], 64)
			locationSet.Add(location{functionIdx: 0})

			// resource profile
			rp := profiles.ResourceProfiles().AppendEmpty()
			//rp.Resource().Attributes().PutStr("service.name", "example-service")
			// TODO: use real stuff
			rp.Resource().Attributes().PutStr(string(semconv.ContainerIDKey), string("0x123454321"))
			rp.SetSchemaUrl(semconv.SchemaURL)

			// scope profile
			sp := rp.ScopeProfiles().AppendEmpty()
			sp.Scope().SetName("example-scope")
			sp.Scope().SetVersion("v0.1.0")

			// profile
			prof := sp.Profiles().AppendEmpty()

			st := prof.SampleType()
			st.SetTypeStrindex(stringSet.Add("samples"))
			st.SetUnitStrindex(stringSet.Add("count"))

			//fIndex := 0

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

				//gadgetCtx.Logger().Infof("kernel_stack: %s, samples: %d\n", kStack, samples)

				// TODO: invert it?
				functions := strings.Split(kStack, "; ")

				// create functions
				//fns := make([]string, 0, len(functions))
				//locs := make([]*pprofile.Location, 0, len(functions))

				sample := prof.Sample().AppendEmpty()
				sample.Values().Append(int64(samples))

				stack := dic.StackTable().AppendEmpty()

				for _, f := range functions {
					// addd the function
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
				loc := locationTable.AppendEmpty()
				l := loc.Line().AppendEmpty()
				l.SetFunctionIndex(val.functionIdx)
			}

			// emit

			req := pprofileotlp.NewExportRequestFromProfiles(profiles)

			//var gzipOption = grpc.UseCompressor(gzip.Name)

			client, ok := o.o.clients[exporterName]
			if !ok {
				return fmt.Errorf("client not found: %q", exporterName)
			}

			res, err := client.Export(gadgetCtx.Context(), req)
			if err != nil {
				gadgetCtx.Logger().Errorf("Exporting profile: %v", err)
				return err
			}

			if r := res.PartialSuccess().RejectedProfiles(); r > 0 {
				gadgetCtx.Logger().Errorf("failed to send %d profiles: %s", r, res.PartialSuccess().ErrorMessage())
				return nil
			}

			gadgetCtx.Logger().Infof("Exported profile!!!!")

			return nil
		}, 0)
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
