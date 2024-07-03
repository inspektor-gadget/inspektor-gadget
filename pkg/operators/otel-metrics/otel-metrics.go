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
	"net/http"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"golang.org/x/exp/constraints"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	name = "otel-metrics"

	Priority                      = 50000
	ParamOtelMetricsEnabled       = "otel-metrics-enabled"
	ParamOtelMetricsListenAddress = "otel-metrics-listen-address"
	ParamOtelMetricsName          = "otel-metrics-name"

	MetricTypeKey       = "key"
	MetricTypeCounter   = "counter"
	MetricTypeGauge     = "gauge"
	MetricTypeHistogram = "histogram"

	AnnotationMetricsExport      = "metrics.export"
	AnnotationMetricsType        = "metrics.type"
	AnnotationMetricsDescription = "metrics.description"
	AnnotationMetricsUnit        = "metrics.unit"
	AnnotationMetricsBoundaries  = "metrics.boundaries"
)

type otelMetricsOperator struct {
	exporter      *prometheus.Exporter
	meterProvider metric.MeterProvider
	initialized   bool

	// if skipListen is set to true, it will not expose the metrics using http
	// this is used mainly for unit tests (you can still use the meterProvider & exporter)
	skipListen bool
}

func (m *otelMetricsOperator) Name() string {
	return name
}

func (m *otelMetricsOperator) Init(globalParams *params.Params) error {
	if m.initialized {
		return nil
	}

	if !globalParams.Get(ParamOtelMetricsEnabled).AsBool() {
		return nil
	}

	exporter, err := prometheus.New()
	if err != nil {
		return fmt.Errorf("initializing otel metrics exporter: %w", err)
	}
	m.exporter = exporter
	m.meterProvider = sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))

	if !m.skipListen {
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())
			err := http.ListenAndServe(globalParams.Get(ParamOtelMetricsListenAddress).AsString(), mux)
			if err != nil {
				log.Errorf("serving otel metrics on: %s", err)
				return
			}
		}()
	}

	m.initialized = true
	return nil
}

func (m *otelMetricsOperator) GlobalParams() api.Params {
	return api.Params{
		{
			Key:          ParamOtelMetricsEnabled,
			DefaultValue: "false",
			TypeHint:     api.TypeBool,
		},
		{
			Key:          ParamOtelMetricsListenAddress,
			DefaultValue: "0.0.0.0:2224",
			TypeHint:     api.TypeString,
		},
	}
}

func (m *otelMetricsOperator) InstanceParams() api.Params {
	return api.Params{
		{
			Key:         ParamOtelMetricsName,
			TypeHint:    api.TypeString,
			Description: "override name of the exported datasource; use a comma-separated list with datasource:newname to specify more than one name",
		},
	}
}

func (m *otelMetricsOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	if !m.initialized {
		return nil, nil
	}

	// extract name mappings; key will be old name (or empty), value the new name
	mappings := make(map[string]string)
	for _, m := range strings.Split(instanceParamValues[ParamOtelMetricsName], ",") {
		names := strings.SplitN(m, ":", 2)
		from := ""
		to := names[0]
		if len(names) == 2 {
			from = to
			to = names[1]
		}
		mappings[from] = to
	}

	instance := &otelMetricsOperatorInstance{
		op:           m,
		collectors:   make(map[datasource.DataSource]*metricsCollector),
		nameMappings: mappings,
	}

	err := instance.init(gadgetCtx)
	if err != nil {
		return nil, err
	}
	return instance, nil
}

func (m *otelMetricsOperator) Priority() int {
	return Priority
}

type otelMetricsOperatorInstance struct {
	op           *otelMetricsOperator
	collectors   map[datasource.DataSource]*metricsCollector
	nameMappings map[string]string
}

func (m *otelMetricsOperatorInstance) Name() string {
	return name
}

type metricsCollector struct {
	meter  metric.Meter
	keys   []func(datasource.Data) attribute.KeyValue
	values []func(context.Context, datasource.Data, attribute.Set)
}

func asInt64Func[T constraints.Integer](extract func(datasource.Data) (T, error)) func(datasource.Data) int64 {
	return func(data datasource.Data) int64 {
		v, _ := extract(data)
		return int64(v)
	}
}

func asInt64(f datasource.FieldAccessor) func(datasource.Data) int64 {
	switch f.Type() {
	default:
		// This should not be called with types other than int
		panic("unsupported field type for asInt64")
	case api.Kind_Int8:
		return asInt64Func(f.Int8)
	case api.Kind_Int16:
		return asInt64Func(f.Int16)
	case api.Kind_Int32:
		return asInt64Func(f.Int32)
	case api.Kind_Int64:
		return asInt64Func(f.Int64)
	case api.Kind_Uint8:
		return asInt64Func(f.Uint8)
	case api.Kind_Uint16:
		return asInt64Func(f.Uint16)
	case api.Kind_Uint32:
		return asInt64Func(f.Uint32)
	case api.Kind_Uint64:
		return asInt64Func(f.Uint64)
	}
}

func asFloat64Func[T constraints.Float](extract func(datasource.Data) (T, error)) func(datasource.Data) float64 {
	return func(data datasource.Data) float64 {
		v, _ := extract(data)
		return float64(v)
	}
}

func asFloat64(f datasource.FieldAccessor) func(datasource.Data) float64 {
	switch f.Type() {
	default:
		// This should not be called with types other than float
		panic("unsupported field type for asFloat4")
	case api.Kind_Float32:
		return asFloat64Func(f.Float32)
	case api.Kind_Float64:
		return asFloat64Func(f.Float64)
	}
}

func (mc *metricsCollector) addKeyFunc(f datasource.FieldAccessor) error {
	name := f.Name()
	switch f.Type() {
	default:
		return fmt.Errorf("unsupported field type for metrics collector: %s", f.Type())
	case api.Kind_String, api.Kind_CString:
		mc.keys = append(mc.keys, func(data datasource.Data) attribute.KeyValue {
			val, _ := f.String(data)
			return attribute.KeyValue{Key: attribute.Key(name), Value: attribute.StringValue(val)}
		})
	case api.Kind_Uint8,
		api.Kind_Uint16,
		api.Kind_Uint32,
		api.Kind_Uint64,
		api.Kind_Int8,
		api.Kind_Int16,
		api.Kind_Int32,
		api.Kind_Int64:
		asIntFn := asInt64(f)
		mc.keys = append(mc.keys, func(data datasource.Data) attribute.KeyValue {
			return attribute.KeyValue{Key: attribute.Key(name), Value: attribute.Int64Value(asIntFn(data))}
		})
	case api.Kind_Float32, api.Kind_Float64:
		asFloatFn := asFloat64(f)
		mc.keys = append(mc.keys, func(data datasource.Data) attribute.KeyValue {
			return attribute.KeyValue{Key: attribute.Key(name), Value: attribute.Float64Value(asFloatFn(data))}
		})
	}
	return nil
}

func (mc *metricsCollector) addValFunc(f datasource.FieldAccessor, metricType string) error {
	var options []metric.InstrumentOption
	if description := f.Annotations()[AnnotationMetricsDescription]; description != "" {
		options = append(options, metric.WithDescription(description))
	}
	if unit := f.Annotations()[AnnotationMetricsUnit]; unit != "" {
		options = append(options, metric.WithUnit(unit))
	}

	switch f.Type() {
	default:
		return fmt.Errorf("unsupported field type for metrics value %q: %s", f.Name(), f.Type())
	case api.Kind_Uint8,
		api.Kind_Uint16,
		api.Kind_Uint32,
		api.Kind_Uint64,
		api.Kind_Int8,
		api.Kind_Int16,
		api.Kind_Int32,
		api.Kind_Int64:
		asIntFn := asInt64(f)
		switch metricType {
		case MetricTypeCounter:
			tOptions := make([]metric.Int64CounterOption, len(options))
			for i, option := range options {
				tOptions[i] = option
			}
			ctr, err := mc.meter.Int64Counter(f.Name(), tOptions...)
			if err != nil {
				return fmt.Errorf("adding metric %s for %q: %w", metricType, f.Name(), err)
			}
			mc.values = append(mc.values, func(ctx context.Context, data datasource.Data, set attribute.Set) {
				ctr.Add(ctx, asIntFn(data), metric.WithAttributeSet(set))
			})
		case MetricTypeGauge:
			tOptions := make([]metric.Int64GaugeOption, len(options))
			for i, option := range options {
				tOptions[i] = option
			}
			ctr, err := mc.meter.Int64Gauge(f.Name(), tOptions...)
			if err != nil {
				return fmt.Errorf("adding metric %s for %q: %w", metricType, f.Name(), err)
			}
			mc.values = append(mc.values, func(ctx context.Context, data datasource.Data, set attribute.Set) {
				ctr.Record(ctx, asIntFn(data), metric.WithAttributeSet(set))
			})
		}
		return nil
	case api.Kind_Float32, api.Kind_Float64:
		asFloatFn := asFloat64(f)
		switch metricType {
		case MetricTypeCounter:
			tOptions := make([]metric.Float64CounterOption, len(options))
			for i, option := range options {
				tOptions[i] = option
			}
			ctr, err := mc.meter.Float64Counter(f.Name(), tOptions...)
			if err != nil {
				return fmt.Errorf("adding metric %s for %q: %w", metricType, f.Name(), err)
			}
			mc.values = append(mc.values, func(ctx context.Context, data datasource.Data, set attribute.Set) {
				ctr.Add(ctx, asFloatFn(data), metric.WithAttributeSet(set))
			})
		case MetricTypeGauge:
			tOptions := make([]metric.Float64GaugeOption, len(options))
			for i, option := range options {
				tOptions[i] = option
			}
			ctr, err := mc.meter.Float64Gauge(f.Name(), tOptions...)
			if err != nil {
				return fmt.Errorf("adding metric %s for %q: %w", metricType, f.Name(), err)
			}
			mc.values = append(mc.values, func(ctx context.Context, data datasource.Data, set attribute.Set) {
				ctr.Record(ctx, asFloatFn(data), metric.WithAttributeSet(set))
			})
		}
		return nil
	}
}

func toFloat64(s string) (float64, error) {
	return strconv.ParseFloat(s, 64)
}

func listToVals[T int64 | float64](list string, conv func(string) (T, error)) ([]T, error) {
	elements := strings.Split(list, ",")
	res := make([]T, 0, len(elements))
	for _, element := range elements {
		v, err := conv(element)
		if err != nil {
			return nil, fmt.Errorf("invalid value: %q: %w", element, err)
		}
		res = append(res, v)
	}
	return res, nil
}

func (mc *metricsCollector) addValHistFunc(f datasource.FieldAccessor) error {
	options := make([]metric.HistogramOption, 0)
	if buckets := f.Annotations()[AnnotationMetricsBoundaries]; buckets != "" {
		boundaries, err := listToVals[float64](buckets, toFloat64)
		if err != nil {
			return fmt.Errorf("adding metric histogram for %q: %w", f.Name(), err)
		}
		options = append(options, metric.WithExplicitBucketBoundaries(boundaries...))
	}
	if description := f.Annotations()[AnnotationMetricsDescription]; description != "" {
		options = append(options, metric.WithDescription(description))
	}
	if unit := f.Annotations()[AnnotationMetricsUnit]; unit != "" {
		options = append(options, metric.WithUnit(unit))
	}

	switch f.Type() {
	default:
		return fmt.Errorf("unsupported field type for metrics value %q: %s", f.Name(), f.Type())
	case api.Kind_Uint8,
		api.Kind_Uint16,
		api.Kind_Uint32,
		api.Kind_Uint64,
		api.Kind_Int8,
		api.Kind_Int16,
		api.Kind_Int32,
		api.Kind_Int64:
		hOptions := make([]metric.Int64HistogramOption, len(options))
		for i, option := range options {
			hOptions[i] = option
		}
		hist, err := mc.meter.Int64Histogram(f.Name(), hOptions...)
		if err != nil {
			return fmt.Errorf("adding metric histogram for %q: %w", f.Name(), err)
		}
		asIntFn := asInt64(f)
		mc.values = append(mc.values, func(ctx context.Context, data datasource.Data, set attribute.Set) {
			hist.Record(ctx, asIntFn(data), metric.WithAttributeSet(set))
		})
		return nil
	case api.Kind_Float32, api.Kind_Float64:
		hOptions := make([]metric.Float64HistogramOption, len(options))
		for i, option := range options {
			hOptions[i] = option
		}
		hist, err := mc.meter.Float64Histogram(f.Name(), hOptions...)
		if err != nil {
			return fmt.Errorf("adding metric histogram for %q: %w", f.Name(), err)
		}
		asFloatFn := asFloat64(f)
		mc.values = append(mc.values, func(ctx context.Context, data datasource.Data, set attribute.Set) {
			hist.Record(ctx, asFloatFn(data), metric.WithAttributeSet(set))
		})
		return nil
	}
}

func (mc *metricsCollector) Collect(ctx context.Context, data datasource.Data) {
	kvs := make([]attribute.KeyValue, 0, len(mc.keys))
	for _, kf := range mc.keys {
		kvs = append(kvs, kf(data))
	}
	kset := attribute.NewSet(kvs...)
	for _, vf := range mc.values {
		vf(ctx, data, kset)
	}
}

func (m *otelMetricsOperatorInstance) init(gadgetCtx operators.GadgetContext) error {
	for _, ds := range gadgetCtx.GetDataSources() {
		annotations := ds.Annotations()
		if annotations[AnnotationMetricsExport] != "true" {
			continue
		}

		metricsName := ds.Name()
		mappedName, ok := m.nameMappings[metricsName]
		if !ok {
			// try empty (unspecified)
			mappedName = m.nameMappings[""]
		}

		if mappedName == "" {
			gadgetCtx.Logger().Warnf("no name found for metric %q, skipping export", metricsName)
			continue
		}

		meter := m.op.meterProvider.Meter(mappedName)

		collector := &metricsCollector{meter: meter}

		hasValueFields := false

		fields := ds.Accessors(false)
		for _, f := range fields {
			fieldName := f.Name()
			metricsType := f.Annotations()[AnnotationMetricsType]
			switch metricsType {
			default:
				continue
			case MetricTypeKey:
				err := collector.addKeyFunc(f)
				if err != nil {
					return fmt.Errorf("adding key for %q: %w", fieldName, err)
				}
			case MetricTypeCounter, MetricTypeGauge:
				err := collector.addValFunc(f, metricsType)
				if err != nil {
					return fmt.Errorf("adding %s for %q: %w", metricsType, fieldName, err)
				}
				hasValueFields = true
			case MetricTypeHistogram:
				err := collector.addValHistFunc(f)
				if err != nil {
					return fmt.Errorf("adding histogram for %q: %w", fieldName, err)
				}
				hasValueFields = true
			}
			gadgetCtx.Logger().Debugf("registered field %q as type %q", fieldName, metricsType)
		}
		if !hasValueFields {
			continue
		}
		m.collectors[ds] = collector
	}
	return nil
}

func (m *otelMetricsOperatorInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	for ds, collector := range m.collectors {
		err := ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
			collector.Collect(gadgetCtx.Context(), data)
			return nil
		}, Priority)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *otelMetricsOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (m *otelMetricsOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

var Operator = &otelMetricsOperator{}
