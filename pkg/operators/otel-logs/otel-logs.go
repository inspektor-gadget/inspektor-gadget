// Copyright 2024-2025 The Inspektor Gadget authors
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

package otellogs

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"

	"github.com/inspektor-gadget/inspektor-gadget/internal/version"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/expr"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	ParamOtelLogsExporter = "otel-logs-exporter"

	AnnotationLogsName = "logs.name"

	AnnotationLogsBody     = "logs.body"
	AnnotationLogsSeverity = "logs.severity"

	FieldNameBody      = "body"
	FieldNameTimestamp = "timestamp"
	FieldNameSeverity  = "severity"

	ExporterOTLPGRPC = "otlp-grpc"

	CompressionNone = "none"
	CompressionGZIP = "gzip"

	TagGroupOtelLogs = "group:OpenTelemetry Logs"
)

var supportedExporters = []string{ExporterOTLPGRPC}

type logConfig struct {
	Exporter    string `json:"exporter" yaml:"exporter"`
	Endpoint    string `json:"endpoint" yaml:"endpoint"`
	Insecure    bool   `json:"insecure" yaml:"insecure"`
	Compression string `json:"compression" yaml:"compression"`
}

type otelLogsOperator struct {
	providers map[string]*sdklog.LoggerProvider
}

func (o *otelLogsOperator) Name() string {
	return "otel-logs"
}

func (o *otelLogsOperator) Init(params *params.Params) error {
	o.providers = make(map[string]*sdklog.LoggerProvider)

	res, _ := resource.New(context.Background(), resource.WithAttributes(
		semconv.ServiceNameKey.String("inspektor-gadget"),
		semconv.ServiceVersionKey.String(version.Version().String()),
	))

	if config.Config == nil {
		return nil
	}

	configs := make(map[string]*logConfig, 0)
	log.Debugf("loading log exporters")
	err := config.Config.UnmarshalKey("operator.otel-logs.exporters", &configs)
	if err != nil {
		log.Warnf("failed to load operator.otel-logs.exporters: %v", err)
	}
	for k, v := range configs {
		if v.Exporter != ExporterOTLPGRPC {
			return fmt.Errorf("unsupported log exporter %q; expected one of %s", v.Exporter,
				strings.Join(supportedExporters, ", "))
		}
		var options []otlploggrpc.Option

		options = append(options, otlploggrpc.WithEndpoint(v.Endpoint))
		if v.Insecure {
			options = append(options, otlploggrpc.WithInsecure())
		}
		switch v.Compression {
		default:
			return fmt.Errorf("unsupported log compression %q", v.Compression)
		case "", CompressionNone:
		case CompressionGZIP:
			options = append(options, otlploggrpc.WithCompressor("gzip"))
		}

		exp, err := otlploggrpc.New(context.Background(), options...)
		if err != nil {
			return fmt.Errorf("creating otlp exporter: %w", err)
		}
		processor := sdklog.NewBatchProcessor(exp)
		provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(processor), sdklog.WithResource(res))
		o.providers[k] = provider
		log.Debugf("> log exporter %q with endpoint %q loaded", k, v.Endpoint)
	}

	return nil
}

func (o *otelLogsOperator) GlobalParams() api.Params {
	return api.Params{}
}

func (o *otelLogsOperator) InstanceParams() api.Params {
	return api.Params{
		&api.Param{
			Key:          ParamOtelLogsExporter,
			Title:        "Logs Exporter",
			Description:  "Exporter to use for log exporting",
			DefaultValue: "",
			Tags:         []string{TagGroupOtelLogs},
		},
	}
}

func (o *otelLogsOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	if len(o.providers) == 0 {
		return nil, nil
	}
	mappings, err := apihelpers.GetStringValuesPerDataSource(instanceParamValues[ParamOtelLogsExporter])
	if err != nil {
		return nil, fmt.Errorf("parsing name mappings: %w", err)
	}
	inst := &otelLogsOperatorInstance{
		o:        o,
		mappings: mappings,
		loggers:  make(map[datasource.DataSource]otellog.Logger),
	}
	err = inst.init(gadgetCtx)
	if err != nil {
		return nil, err
	}
	return inst, nil
}

func (o *otelLogsOperator) Priority() int {
	return 9999
}

type otelLogsOperatorInstance struct {
	o        *otelLogsOperator
	mappings map[string]string
	loggers  map[datasource.DataSource]otellog.Logger
}

func (o *otelLogsOperatorInstance) init(gadgetCtx operators.GadgetContext) error {
	for _, ds := range gadgetCtx.GetDataSources() {
		annotations := ds.Annotations()

		// Find mapping
		exporterName, ok := o.mappings[ds.Name()]
		if !ok {
			exporterName, ok = o.mappings[""]
			if !ok {
				continue
			}
		}

		exporter, ok := o.o.providers[exporterName]
		if !ok {
			return fmt.Errorf("exporter not found: %q", exporterName)
		}

		loggerName := annotations[AnnotationLogsName]
		if loggerName == "" {
			loggerName = gadgetCtx.ImageName()
		}

		gadgetCtx.Logger().Debugf("logging %q to exporter %q", ds.Name(), exporterName)
		o.loggers[ds] = exporter.Logger(loggerName)
	}
	return nil
}

// copyBytesToLogValue copies the bytes and returns an otellog.Value.
// This complies with otellog.BytesValue docs which state that the
// passed slice must not be modified after the call.
func copyBytesToLogValue(b []byte) otellog.Value {
	cp := make([]byte, len(b))
	copy(cp, b)
	return otellog.BytesValue(cp)
}

// makeAttrPrep returns a function that will produce an otellog.KeyValue for the provided field.
// It handles Bytes (raw string if valid UTF-8, base64 otherwise) and Bool (Int64Value 0/1) specially and falls back
// to datasource.GetKeyValueFunc for supported scalar kinds.
func makeAttrPrep(f datasource.FieldAccessor, nameOverride string) (func(data datasource.Data) otellog.KeyValue, error) {
	name := f.FullName()
	if nameOverride != "" {
		name = nameOverride
	}

	// If the field cannot contain a value or is an empty/container, return nil preparer
	if f.Type() == api.Kind_Invalid || datasource.FieldFlagEmpty.In(f.Flags()) || datasource.FieldFlagContainer.In(f.Flags()) {
		return nil, nil
	}

	kvf, err := datasource.GetKeyValueFunc[string, otellog.Value](f, name, otellog.Int64Value, otellog.Float64Value, otellog.StringValue, otellog.BoolValue, copyBytesToLogValue)
	if err != nil {
		return nil, err
	}
	return func(data datasource.Data) otellog.KeyValue {
		key, val := kvf(data)
		return otellog.KeyValue{Key: key, Value: val}
	}, nil
}

func (o *otelLogsOperatorInstance) Name() string {
	return "otel-logs"
}

func (o *otelLogsOperatorInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	for ds, logger := range o.loggers {
		fields := ds.Accessors(false)
		annotations := ds.Annotations()

		prep := make([]func(data datasource.Data) otellog.KeyValue, 0)
		kvCount := 0

		var bodySet bool

		fns := make([]func(datasource.Data, *otellog.Record), 0)

		// fixed severity by annotation
		if severity, ok := annotations[AnnotationLogsSeverity]; ok {
			sv, err := strconv.ParseFloat(severity, 64)
			if err != nil {
				return fmt.Errorf("invalid log severity %q: %w", severity, err)
			}
			fns = append(fns, func(data datasource.Data, record *otellog.Record) {
				record.SetSeverity(otellog.Severity(sv))
			})
		}

		// body string by annotation
		if bodyString, ok := annotations[AnnotationLogsBody]; ok {
			prog, err := expr.CompileStringProgram(ds, bodyString)
			if err != nil {
				return fmt.Errorf("compiling expression %q: %w", bodyString, err)
			}
			fns = append(fns, func(data datasource.Data, record *otellog.Record) {
				s, err := expr.Run(prog, data)
				if err != nil {
					return
				}
				record.SetBody(otellog.StringValue(s.(string)))
			})
			bodySet = true
		}

		// First, collect any explicitly annotated fields (those with `logs.name` per-field).
		for _, f := range fields {
			// Skip parent fields that have subfields — their children fully represent the data.
			if len(f.SubFields()) > 0 {
				continue
			}

			fieldAnnotations := f.Annotations()
			name, ok := fieldAnnotations[AnnotationLogsName]
			if !ok {
				continue
			}

			// Skip fields that don't carry a value (invalid/empty/container)
			if f.Type() == api.Kind_Invalid ||
				datasource.FieldFlagEmpty.In(f.Flags()) ||
				datasource.FieldFlagContainer.In(f.Flags()) {
				continue
			}

			switch name {
			case FieldNameBody:
				fns = append(fns, func(data datasource.Data, record *otellog.Record) {
					str, _ := f.String(data)
					record.SetBody(otellog.StringValue(str))
				})
				bodySet = true
				continue
			case FieldNameTimestamp:
				ts, err := datasource.AsInt64(f)
				if err != nil {
					return fmt.Errorf("using field %q as %q: %w", f.FullName(), name, err)
				}
				fns = append(fns, func(data datasource.Data, record *otellog.Record) {
					record.SetObservedTimestamp(time.Unix(0, ts(data)*int64(time.Microsecond)))
				})
				continue
			case FieldNameSeverity:
				severity, err := datasource.AsInt64(f)
				if err != nil {
					return fmt.Errorf("using field %q as %q: %w", f.FullName(), name, err)
				}
				fns = append(fns, func(data datasource.Data, record *otellog.Record) {
					record.SetSeverity(otellog.Severity(severity(data)))
				})
				continue
			}

			// Build attribute prep function via helper.
			p, err := makeAttrPrep(f, name)
			if err != nil {
				return fmt.Errorf("getting key/val func for %s.%s: %w", ds.Name(), f.FullName(), err)
			}
			if p == nil {
				continue
			}
			prep = append(prep, p)
			kvCount++
		}

		// If there were no annotated fields producing attributes and no body setter,
		// fall back to encoding the entire event as attributes by adding all fields.
		// This ensures the event is represented via attributes even when `logs.body`
		// isn't set and no per-field annotations exist.
		if kvCount == 0 && !bodySet {
			for _, f := range fields {
				// Skip parent fields that have subfields — their children fully represent the data.
				if len(f.SubFields()) > 0 {
					continue
				}
				// Build attr prep using full field name
				p, err := makeAttrPrep(f, "")
				if err != nil {
					return fmt.Errorf("getting key/val func for %s.%s: %w", ds.Name(), f.FullName(), err)
				}
				if p == nil {
					continue
				}
				prep = append(prep, p)
				kvCount++
			}
		}

		ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
			var rec otellog.Record

			// Collect attributes
			attribs := make([]otellog.KeyValue, 0, kvCount)
			for _, p := range prep {
				attribs = append(attribs, p(data))
			}
			rec.AddAttributes(attribs...)

			// Set other values
			for _, f := range fns {
				f(data, &rec)
			}

			// If no body setter was provided, ensure the record still has a body
			// (empty string). This makes the exporter emit the event encoded via
			// attributes even when `logs.body` isn't set.
			if !bodySet {
				rec.SetBody(otellog.StringValue(""))
			}

			rec.SetTimestamp(time.Now())

			logger.Emit(gadgetCtx.Context(), rec)
			return nil
		}, 10000)
	}
	return nil
}

func (o *otelLogsOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (o *otelLogsOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (o *otelLogsOperatorInstance) Close(gadgetCtx operators.GadgetContext) error {
	return nil
}

var Operator = &otelLogsOperator{}

func init() {
	operators.RegisterDataOperator(Operator)
}
