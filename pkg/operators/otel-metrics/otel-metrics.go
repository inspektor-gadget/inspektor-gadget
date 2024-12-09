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

// Package otelmetrics implements an operator that can export data sources to OpenTelemetry metrics.
package otelmetrics

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	otelprometheus "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/histogram"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ebpftypes "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	name = "otel-metrics"

	Priority                      = 9995 // slightly before CLI so we can reroute output there
	ParamOtelMetricsListen        = "otel-metrics-listen"
	ParamOtelMetricsListenAddress = "otel-metrics-listen-address"
	ParamOtelMetricsName          = "otel-metrics-name"
	ParamOtelMetricsExporter      = "otel-metrics-exporter"
	ParamOtelMetricsPrintInterval = "otel-metrics-print-interval"

	MetricTypeKey       = "key"
	MetricTypeCounter   = "counter"
	MetricTypeGauge     = "gauge"
	MetricTypeHistogram = "histogram"

	AnnotationMetricsCollect     = "metrics.collect"
	AnnotationMetricsPrint       = "metrics.print"
	AnnotationMetricsType        = "metrics.type"
	AnnotationMetricsDescription = "metrics.description"
	AnnotationMetricsUnit        = "metrics.unit"
	AnnotationMetricsBoundaries  = "metrics.boundaries"

	AnnotationImplicitCounterName        = "metrics.implicit-counter.name"
	AnnotationImplicitCounterDescription = "metrics.implicit-counter.description"

	PrintDataSourceSuffix = "rendered"
	PrintFieldName        = "text"

	HistogramOutputMode = "histogram"

	MinPrintInterval = time.Millisecond * 25
)

var renderedDsCliAnnotations = map[string]string{
	"cli.supported-output-modes": HistogramOutputMode,
	"cli.default-output-mode":    HistogramOutputMode,
	"cli.clear-screen-before":    "true",
}

type metricsConfig struct {
	Exporter    string        `json:"exporter" yaml:"exporter"`
	Endpoint    string        `json:"endpoint" yaml:"endpoint"`
	Insecure    bool          `json:"insecure" yaml:"insecure"`
	Temporality string        `json:"temporality" yaml:"temporality"`
	Interval    time.Duration `json:"interval" yaml:"interval"`
}

func deltaSelector(kind sdkmetric.InstrumentKind) metricdata.Temporality {
	switch kind {
	case sdkmetric.InstrumentKindCounter,
		sdkmetric.InstrumentKindGauge,
		sdkmetric.InstrumentKindHistogram,
		sdkmetric.InstrumentKindObservableGauge,
		sdkmetric.InstrumentKindObservableCounter:
		return metricdata.DeltaTemporality
	case sdkmetric.InstrumentKindUpDownCounter,
		sdkmetric.InstrumentKindObservableUpDownCounter:
		return metricdata.CumulativeTemporality
	}
	panic("unknown instrument kind")
}

type otelMetricsOperator struct {
	// exporter is the global exporter instance
	exporter      *otelprometheus.Exporter
	meterProvider metric.MeterProvider

	providers map[string]metric.MeterProvider

	// if skipListen is set to true, it will not expose the metrics using http
	// this is used mainly for unit tests (you can still use the meterProvider & exporter)
	skipListen bool
}

func (m *otelMetricsOperator) Name() string {
	return name
}

func (m *otelMetricsOperator) Init(globalParams *params.Params) error {
	// Initialize provider map
	m.providers = map[string]metric.MeterProvider{}

	// Initialize named metric providers
	mc := make(map[string]*metricsConfig, 0)
	if config.Config != nil {
		log.Debug("loading metric exporters")
		err := config.Config.UnmarshalKey("operator.otel-metrics.exporters", &mc)
		if err != nil {
			log.Warnf("failed to load operator.otel-metrics.exporters: %v", err)
		}
		for k, v := range mc {
			switch v.Exporter {
			default:
				log.Errorf("invalid metric exporter %q", v.Exporter)
			case "otlp-grpc":
				if v.Endpoint == "" {
					return fmt.Errorf("endpoint required for otlp-grpc exporter")
				}
				var options []otlpmetricgrpc.Option
				options = append(options, otlpmetricgrpc.WithEndpoint(v.Endpoint))
				if v.Insecure {
					options = append(options, otlpmetricgrpc.WithInsecure())
				}
				switch v.Temporality {
				case "", "cumulative":
				case "delta":
					options = append(options, otlpmetricgrpc.WithTemporalitySelector(deltaSelector))
				}
				otlpcollector, err := otlpmetricgrpc.New(
					context.Background(),
					options...,
				)
				if err != nil {
					return fmt.Errorf("initializting otlp metrics collector")
				}
				var periodicReaderOptions []sdkmetric.PeriodicReaderOption
				if v.Interval > 0 {
					periodicReaderOptions = append(periodicReaderOptions, sdkmetric.WithInterval(v.Interval))
				}
				m.providers[k] = sdkmetric.NewMeterProvider(
					sdkmetric.WithReader(
						sdkmetric.NewPeriodicReader(otlpcollector, periodicReaderOptions...),
					),
				)
				log.Debugf("initialized metric provider %q", k)
			}
		}
	}

	if !globalParams.Get(ParamOtelMetricsListen).AsBool() {
		return nil
	}

	// create a global prometheus collector/exporter; this will be exposed using an HTTP endpoint, if activated
	exporter, err := otelprometheus.New()
	if err != nil {
		return fmt.Errorf("initializing otel metrics exporter: %w", err)
	}
	m.exporter = exporter
	m.meterProvider = sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))

	// Start HTTP listener for the global exporter
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
	return nil
}

func (m *otelMetricsOperator) GlobalParams() api.Params {
	return api.Params{
		{
			Key:          ParamOtelMetricsListen,
			DefaultValue: "false",
			TypeHint:     api.TypeBool,
			Description:  "enable OpenTelemetry metrics listener (Prometheus compatible) endpoint",
		},
		{
			Key:          ParamOtelMetricsListenAddress,
			DefaultValue: "0.0.0.0:2224",
			TypeHint:     api.TypeString,
			Description:  "address and port to create the OpenTelemetry metrics listener (Prometheus compatible) on",
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
		{
			Key:          ParamOtelMetricsPrintInterval,
			TypeHint:     api.TypeDuration,
			Description:  "interval to use when printing metrics; minimum is 25ms",
			DefaultValue: "1000ms",
		},
		{
			Key:          ParamOtelMetricsExporter,
			TypeHint:     api.TypeString,
			Description:  "name of the configured metric provider to use; leave empty to use the default exporter",
			DefaultValue: "",
		},
	}
}

func (m *otelMetricsOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	// extract name mappings; key will be old name (or empty), value the new name
	mappings, err := apihelpers.GetStringValuesPerDataSource(instanceParamValues[ParamOtelMetricsName])
	if err != nil {
		return nil, fmt.Errorf("parsing name mappings: %w", err)
	}

	params := apihelpers.ToParamDescs(m.InstanceParams()).ToParams()
	err = params.CopyFromMap(instanceParamValues, "")
	if err != nil {
		return nil, err
	}
	printInterval := params.Get(ParamOtelMetricsPrintInterval).AsDuration()
	if printInterval < MinPrintInterval {
		return nil, fmt.Errorf("parsing print interval: expected at least %s, got %s", MinPrintInterval, printInterval)
	}

	instance := &otelMetricsOperatorInstance{
		op:            m,
		collectors:    make(map[datasource.DataSource]*metricsCollector),
		nameMappings:  mappings,
		printInterval: printInterval,
		done:          make(chan struct{}),
	}

	// named metric providers are only evaluated on the server side for now
	provider := params.Get(ParamOtelMetricsExporter).AsString()
	if provider != "" {
		p, ok := m.providers[provider]
		if !ok {
			if gadgetCtx.IsRemoteCall() {
				// Warn, if the selected metrics provider is not available, and we're running on the server
				gadgetCtx.Logger().Warnf("no remote metrics provider found with name %q", provider)
			} else {
				// Only as debug message, if we're running on the client
				gadgetCtx.Logger().Debugf("no local metrics provider found with name %q", provider)
			}
		} else {
			instance.provider = p
		}
	}

	err = instance.init(gadgetCtx)
	if err != nil {
		return nil, err
	}
	return instance, nil
}

func (m *otelMetricsOperator) Priority() int {
	return Priority
}

type otelMetricsOperatorInstance struct {
	op            *otelMetricsOperator
	collectors    map[datasource.DataSource]*metricsCollector
	nameMappings  map[string]string
	outputDS      datasource.DataSource
	outputField   datasource.FieldAccessor
	printInterval time.Duration
	provider      metric.MeterProvider
	done          chan struct{}
	wg            sync.WaitGroup
}

func (m *otelMetricsOperatorInstance) Name() string {
	return name
}

type metricsCollector struct {
	meter             metric.Meter
	keys              []func(datasource.Data) attribute.KeyValue
	values            []func(context.Context, datasource.Data, attribute.Set)
	mappedName        string
	output            bool
	exporter          *otelprometheus.Exporter
	meterProvider     *sdkmetric.MeterProvider
	useGlobalProvider bool
}

func (mc *metricsCollector) addKeyFunc(f datasource.FieldAccessor) error {
	vf, err := datasource.GetKeyValueFunc[attribute.Key, attribute.Value](f, attribute.Int64Value, attribute.Float64Value, attribute.StringValue)
	if err != nil {
		return err
	}
	mc.keys = append(mc.keys, func(ds datasource.Data) attribute.KeyValue {
		key, val := vf(ds)
		return attribute.KeyValue{Key: key, Value: val}
	})
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
		asIntFn, _ := datasource.AsInt64(f) // error can't happen
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
		asFloatFn, _ := datasource.AsFloat64(f) // error can't happen
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

func (mc *metricsCollector) addValHistFunc(ds datasource.DataSource, f datasource.FieldAccessor) error {
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
	case api.ArrayOf(api.Kind_Uint32), api.ArrayOf(api.Kind_Uint64):
		// Calc buckets
		typeLen := 4
		var extractor func(b []byte) uint64
		switch f.Type() {
		case api.ArrayOf(api.Kind_Uint64):
			typeLen = 8
			extractor = ds.ByteOrder().Uint64
		case api.ArrayOf(api.Kind_Uint32):
			typeLen = 4
			extractor = func(b []byte) uint64 { return uint64(ds.ByteOrder().Uint32(b)) }
		default:
			return fmt.Errorf("expected array of uint32 or uint64, got %v", f.Type())
		}
		alen := int(f.Size()) / typeLen

		bucketVals := make([]int64, alen)
		bucketValsFloat := make([]float64, alen)
		for i := range bucketVals {
			bucketVals[i] = int64(1 << i)
			bucketValsFloat[i] = float64(bucketVals[i])
		}

		options = append(options, metric.WithExplicitBucketBoundaries(bucketValsFloat...))
		hOptions := make([]metric.Int64HistogramOption, len(options))
		for i, option := range options {
			hOptions[i] = option
		}

		hist, err := mc.meter.Int64Histogram(f.Name(), hOptions...)
		if err != nil {
			return fmt.Errorf("adding metric histogram for %q: %w", f.Name(), err)
		}
		mc.values = append(mc.values, func(ctx context.Context, data datasource.Data, set attribute.Set) {
			b := f.Get(data)
			if len(b)%typeLen != 0 {
				return
			}
			for i := 0; i < alen; i++ {
				val := extractor(b[i*typeLen:])
				// This looks counterintuitive - and it is. For every entry in our sources bucket, we have to emit
				// a `hist.Record()` with a value from the given bucket, to replicate the entry count in that bucket.
				// We sadly have no direct access to the underlying bucket to optimize this, but we should look into
				// alternative (more optimized) solutions.
				for range val {
					hist.Record(ctx, bucketVals[i], metric.WithAttributeSet(set))
				}
			}
		})
		return nil
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
		asIntFn, _ := datasource.AsInt64(f) // error can't happen
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
		asFloatFn, _ := datasource.AsFloat64(f) // error can't happen
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
		metricsCollect := annotations[AnnotationMetricsCollect] == "true"
		// We only allow printing if the gadget is _not_ running remotely
		metricsPrint := annotations[AnnotationMetricsPrint] == "true" && !gadgetCtx.IsRemoteCall()

		// Neither collecting nor printing, do nothing for this data source
		if !metricsCollect && !metricsPrint {
			continue
		}

		if metricsPrint {
			gadgetCtx.Logger().Debugf("enabling print for %s", ds.Name())

			// Disable original data source to avoid other operators subscribing to it
			ds.Unreference()

			// Create a new data source for the output with a single field
			odsName := fmt.Sprintf("%s-%s", ds.Name(), PrintDataSourceSuffix)
			ods, err := gadgetCtx.RegisterDataSource(datasource.TypeSingle, odsName)
			if err != nil {
				return fmt.Errorf("registering %q: %w", odsName, err)
			}

			// Set default annotations
			for k, v := range renderedDsCliAnnotations {
				ods.AddAnnotation(k, v)
			}

			// Use annotations from the original data source
			for k, v := range ds.Annotations() {
				ods.AddAnnotation(k, v)
			}

			f, err := ods.AddField(PrintFieldName, api.Kind_String, datasource.WithAnnotations(map[string]string{"content-type": "text/plain"}))
			if err != nil {
				return fmt.Errorf("adding field %q: %w", PrintFieldName, err)
			}

			// TODO: Store these fields per datasource to support multiple datasources
			m.outputDS = ods
			m.outputField = f
		}

		// we only use the global instance (if available) if there's an explicit name mapping available;
		// otherwise we'll fallback to using a dedicated local registry/collector instance
		useGlobal := false
		mappedName, ok := m.nameMappings[ds.Name()]
		if ok && (m.op.exporter != nil || m.provider != nil) {
			useGlobal = true
		} else if ok {
			gadgetCtx.Logger().Warnf("global exporter not configured, using local metric instance")
		}

		// If mapped name is empty, it hasn't been explicitly set (or set to empty), so we will use the data source name
		if mappedName == "" {
			mappedName = ds.Name()
		}

		gadgetCtx.Logger().Debugf("collecting metrics for data source %q as %q", ds.Name(), mappedName)

		m.collectors[ds] = &metricsCollector{
			output:            metricsPrint,
			mappedName:        mappedName,
			useGlobalProvider: useGlobal,
		}
	}
	return nil
}

func (m *otelMetricsOperatorInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	for ds, collector := range m.collectors {
		if collector.useGlobalProvider {
			if m.provider != nil {
				gadgetCtx.Logger().Debugf("using metric provider for collector %q", collector.mappedName)
				// using the global meter provider to export to Prometheus
				collector.meter = m.provider.Meter(collector.mappedName)
			} else {
				gadgetCtx.Logger().Debugf("using global metric provider for collector %q", collector.mappedName)
				// using the global meter provider to export to Prometheus
				collector.meter = m.op.meterProvider.Meter(collector.mappedName)
			}
		} else {
			// Initialize a local instance
			gadgetCtx.Logger().Debugf("using local metric provider for collector %q", collector.mappedName)
			registry := prometheus.NewRegistry()
			exporter, err := otelprometheus.New(otelprometheus.WithRegisterer(registry))
			if err != nil {
				return fmt.Errorf("creating prometheus registry: %w", err)
			}
			collector.exporter = exporter
			collector.meterProvider = sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
			collector.meter = collector.meterProvider.Meter(collector.mappedName)
		}

		hasValueFields := false

		// Support an implicit counter
		if implicitCounter := ds.Annotations()[AnnotationImplicitCounterName]; implicitCounter != "" {
			tOptions := make([]metric.Int64CounterOption, 0)
			if implicitCounterDescription := ds.Annotations()[AnnotationImplicitCounterDescription]; implicitCounterDescription != "" {
				tOptions = append(tOptions, metric.WithDescription(implicitCounterDescription))
			}
			ctr, err := collector.meter.Int64Counter(implicitCounter, tOptions...)
			if err != nil {
				return fmt.Errorf("adding implicit counter %q: %w", implicitCounter, err)
			}
			collector.values = append(collector.values, func(ctx context.Context, data datasource.Data, set attribute.Set) {
				ctr.Add(ctx, 1, metric.WithAttributeSet(set))
			})
			hasValueFields = true
		}

		fields := ds.Accessors(false)
		for _, f := range fields {
			fieldName := f.Name()
			metricsType := f.Annotations()[AnnotationMetricsType]

			// Try to auto-apply metricsType from tags
			if metricsType == "" {
				// tbd: should we rather handle this mapping in the eBPF operator to keep the types there?
				if f.HasAnyTagsOf("type:"+ebpftypes.HistogramSlotU32TypeName, "type:"+ebpftypes.HistogramSlotU64TypeName) {
					metricsType = MetricTypeHistogram
				} else if f.HasAnyTagsOf("type:"+ebpftypes.CounterU32TypeName, "type:"+ebpftypes.CounterU64TypeName) {
					metricsType = MetricTypeCounter
				} else if f.HasAnyTagsOf("type:"+ebpftypes.GaugeU32TypeName, "type:"+ebpftypes.GaugeU64TypeName) {
					metricsType = MetricTypeGauge
				}
			}

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
				err := collector.addValHistFunc(ds, f)
				if err != nil {
					return fmt.Errorf("adding histogram for %q: %w", fieldName, err)
				}
				hasValueFields = true
			}
			gadgetCtx.Logger().Debugf("registered field %q as type %q", fieldName, metricsType)
		}
		if !hasValueFields {
			gadgetCtx.Logger().Debugf("no value fields found for metrics %q", collector.mappedName)
			continue
		}

		err := ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
			collector.Collect(gadgetCtx.Context(), data)
			return nil
		}, Priority)
		if err != nil {
			return err
		}
	}

	// If we registered an output datasource, use it
	if m.outputDS != nil && m.printInterval > 0 {
		// Start printer
		m.wg.Add(1)
		go m.PrintMetrics(gadgetCtx)
	}
	return nil
}

func (m *otelMetricsOperatorInstance) PrintMetrics(gadgetCtx operators.GadgetContext) {
	defer m.wg.Done()
	// Periodically print using the fetch interval
	ticker := time.NewTicker(m.printInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-ticker.C:
			// collect metrics
			md := make(map[*otelprometheus.Exporter]*metricdata.ResourceMetrics)

			var out strings.Builder
			for _, collector := range m.collectors {
				exporter := m.op.exporter
				if collector.exporter != nil {
					exporter = collector.exporter
				}
				if exporter == nil {
					continue
				}

				rm, ok := md[exporter]
				if !ok {
					// Not yet collected, so collect
					rm = &metricdata.ResourceMetrics{}
					err := exporter.Collect(gadgetCtx.Context(), rm)
					if err != nil {
						gadgetCtx.Logger().Errorf("collecting metrics: %v", err)
						return
					}
					md[exporter] = rm
				}

				// Find metric in ResourceMetrics
				for _, sm := range rm.ScopeMetrics {
					if sm.Scope.Name != collector.mappedName {
						continue
					}

					for _, metric := range sm.Metrics {
						fmt.Fprintln(&out, metric.Name)
						switch t := metric.Data.(type) {
						case metricdata.Histogram[int64]:
							for _, dp := range t.DataPoints {
								last := uint64(0)
								v := make([]histogram.Interval, 0, len(dp.Bounds))
								for bucket, high := range dp.Bounds {
									v = append(v, histogram.Interval{
										Count: dp.BucketCounts[bucket],
										Start: last,
										End:   uint64(high),
									})
									last = uint64(high)
								}
								h := histogram.Histogram{
									Unit:      histogram.Unit(metric.Unit),
									Intervals: v,
								}
								fmt.Fprintln(&out, h.String())
							}
						}
					}
					break
				}
			}

			ps, err := m.outputDS.NewPacketSingle()
			if err != nil {
				gadgetCtx.Logger().Errorf("error creating packet: %v", err)
				return
			}
			m.outputField.PutString(ps, out.String())
			m.outputDS.EmitAndRelease(ps)
		}
	}
}

func (m *otelMetricsOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (m *otelMetricsOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (m *otelMetricsOperatorInstance) Close(gadgetCtx operators.GadgetContext) error {
	gadgetCtx.Logger().Debug("shutting down metrics")
	close(m.done)
	ctx := context.Background()
	for _, collector := range m.collectors {
		if collector.meterProvider != nil {
			collector.meterProvider.Shutdown(ctx)
			collector.meterProvider = nil
		}
		if collector.exporter != nil {
			collector.exporter.Shutdown(ctx)
			collector.exporter = nil
		}
	}
	m.wg.Wait()
	return nil
}

var Operator = &otelMetricsOperator{}

func init() {
	operators.RegisterDataOperator(Operator)
}
