// Copyright 2023 The Inspektor Gadget authors
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

package prometheus

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	otelmetric "go.opentelemetry.io/otel/metric"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/prometheus/config"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

const (
	// Define constants again because importing the operators doesn't work
	LocalManagerName   = "LocalManager"
	KubeManagerName    = "KubeManager"
	ParamContainerName = "containername"
	ParamPodName       = "podname"
	ParamNamespace     = "namespace"
)

type Counter struct {
	config.Metric
}

type Gauge struct {
	config.Metric

	registration otelmetric.Registration
}

type Instruments struct {
	Counters []*Counter
	Gauges   []*Gauge
}

func CreateMetrics(ctx context.Context, config *config.Config, meterProvider otelmetric.MeterProvider) (func(), error) {
	runtime := &local.Runtime{}
	instruments := &Instruments{}

	meter := meterProvider.Meter(fmt.Sprintf("gadgets.inspektor-gadget.io/%s", config.MetricsName))

	for _, metric := range config.Metrics {
		switch metric.Type {
		case "counter":
			counter, err := createCounter(ctx, runtime, &metric, meter)
			if err != nil {
				return nil, err
			}
			instruments.Counters = append(instruments.Counters, counter)
		case "gauge":
			gauge, err := createGauge(ctx, runtime, &metric, meter)
			if err != nil {
				return nil, err
			}
			instruments.Gauges = append(instruments.Gauges, gauge)
		default:
			return nil, fmt.Errorf("metric type %s not supported", metric.Type)
		}
	}

	return func() {
		for _, gauge := range instruments.Gauges {
			if gauge.registration != nil {
				gauge.registration.Unregister()
			}
		}
	}, nil
}

func handleMetric(
	ctx context.Context,
	metricCommon *config.Metric,
	runtime runtime.Runtime,
) (*gadgetcontext.GadgetContext, parser.Parser, error) {
	runtimeParams := runtime.ParamDescs().ToParams()

	gadgetDesc := gadgetregistry.Get(metricCommon.Category, metricCommon.Gadget)
	if gadgetDesc == nil {
		return nil, nil, fmt.Errorf("gadget %s/%s not found",
			metricCommon.Category, metricCommon.Gadget)
	}
	parser := gadgetDesc.Parser()

	gadgetParams := gadgetDesc.ParamDescs().ToParams()

	validOperators := operators.GetOperatorsForGadget(gadgetDesc)
	operatorsParamCollection := validOperators.ParamCollection()

	// Handle namespace/pod/container filtering logic in the kubemanager and localmanager operators
	for i, filter := range metricCommon.Selector {
		parts := strings.Split(filter, ":")
		if len(parts) != 2 {
			return nil, nil, fmt.Errorf("invalid filter: %s", filter)
		}

		// These filters aren't supported by the container collection yet. Implement those
		// cases in user space.
		if strings.HasSuffix(parts[0], "!") ||
			strings.HasPrefix(parts[0], "~") ||
			strings.HasPrefix(parts[0], ">=") {
			continue
		}

		switch parts[0] {
		case "namespace":
			operatorsParamCollection.Set(KubeManagerName, ParamNamespace, parts[1])
			metricCommon.Selector[i] = ""
		case "pod":
			operatorsParamCollection.Set(KubeManagerName, ParamPodName, parts[1])
			metricCommon.Selector[i] = ""
		case "container":
			operatorsParamCollection.Set(LocalManagerName, ParamContainerName, parts[1])
			operatorsParamCollection.Set(KubeManagerName, ParamContainerName, parts[1])
			metricCommon.Selector[i] = ""
		}
	}

	// FIXME: this is actually a no-op as the operators are only initialized once.
	operatorsGlobalParamsCollection := operators.GlobalParamsCollection()
	err := validOperators.Init(operatorsGlobalParamsCollection)
	if err != nil {
		return nil, nil, fmt.Errorf("initializing operators: %w", err)
	}

	gadgetCtx := gadgetcontext.New(
		ctx,
		metricCommon.Name,
		runtime,
		runtimeParams,
		gadgetDesc,
		gadgetParams,
		nil, // TODO: where do I get this?
		operatorsParamCollection,
		parser,
		logger.DefaultLogger(),
		0,
	)

	// Handle remaining filtering logic in the parser
	filters := []string{}
	for _, selector := range metricCommon.Selector {
		if selector != "" {
			filters = append(filters, selector)
		}
	}

	if err := parser.SetFilters(filters); err != nil {
		return nil, nil, fmt.Errorf("setting filters: %w", err)
	}

	return gadgetCtx, parser, nil
}

func createCounter(
	ctx context.Context,
	runtime runtime.Runtime,
	metric *config.Metric,
	meter otelmetric.Meter,
) (*Counter, error) {
	counter := &Counter{Metric: *metric}

	gadgetCtx, parser, err := handleMetric(ctx, &counter.Metric, runtime)
	if err != nil {
		return nil, err
	}

	if gadgetCtx.GadgetDesc().Type() != gadgets.TypeTrace {
		return nil, fmt.Errorf("counter %s: only tracer gadgets are supported", counter.Name)
	}

	isInt := true

	// Determine kind of counter (int vs float)
	if metric.Field != "" {
		typ, err := parser.GetColKind(counter.Field)
		if err != nil {
			return nil, err
		}

		switch typ {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			isInt = true
		case reflect.Float32, reflect.Float64:
			isInt = false
		default:
			return nil, fmt.Errorf("counter %s: unsupported field type %s", counter.Name, typ)
		}
	}

	var cb func(any)

	attrsGetter, err := parser.AttrsGetter(counter.Labels)
	if err != nil {
		return nil, err
	}

	if isInt {
		otelCounter, err := meter.Int64Counter(counter.Name)
		if err != nil {
			return nil, err
		}

		var fieldGetter func(any) int64

		if counter.Field != "" {
			fieldGetter, err = parser.ColIntGetter(counter.Field)
			if err != nil {
				return nil, err
			}
		}

		cb = func(ev any) {
			attrs := attrsGetter(ev)
			incr := int64(1)
			if fieldGetter != nil {
				incr = fieldGetter(ev)
			}
			otelCounter.Add(ctx, incr, otelmetric.WithAttributes(attrs...))
		}
	} else {
		otelCounter, err := meter.Float64Counter(counter.Name)
		if err != nil {
			return nil, err
		}

		var fieldGetter func(any) float64

		if counter.Field != "" {
			fieldGetter, err = parser.ColFloatGetter(counter.Field)
			if err != nil {
				return nil, err
			}
		}

		cb = func(ev any) {
			attrs := attrsGetter(ev)
			incr := float64(1.0)
			if fieldGetter != nil {
				incr = fieldGetter(ev)
			}
			otelCounter.Add(ctx, incr, otelmetric.WithAttributes(attrs...))
		}
	}

	parser.SetEventCallback(cb)

	go func() {
		if _, err = runtime.RunGadget(gadgetCtx); err != nil {
			gadgetCtx.Logger().Errorf("running gadget: %s", err)
		}
	}()

	return counter, nil
}

func createGauge(
	ctx context.Context,
	runtime runtime.Runtime,
	metric *config.Metric,
	meter otelmetric.Meter,
) (*Gauge, error) {
	gauge := &Gauge{Metric: *metric}
	gadgetCtx, parser, err := handleMetric(ctx, &gauge.Metric, runtime)
	if err != nil {
		return nil, err
	}

	if gadgetCtx.GadgetDesc().Type() != gadgets.TypeOneShot {
		return nil, fmt.Errorf("gauge %s: only one-shot gadgets are supported", gauge.Name)
	}

	//if gauge.Field != "" {
	//	return nil, fmt.Errorf("field is not supported for gauges yet")
	//}

	entriesChan := make(chan any, 1)

	// One-shot gadgets provide an array of entries in the callback. Use this channel to store
	// this that will be processed in the otel callback
	cb := func(ev any) {
		entriesChan <- ev
	}

	parser.SetEventCallback(cb)

	isInt := true

	// Determine kind of gauge (int vs float)
	if metric.Field != "" {
		typ, err := parser.GetColKind(gauge.Field)
		if err != nil {
			return nil, err
		}

		switch typ {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			isInt = true
		case reflect.Float32, reflect.Float64:
			isInt = false
		default:
			return nil, fmt.Errorf("gauge %s: unsupported field type %s", gauge.Name, typ)
		}
	}

	var intGauge otelmetric.Int64ObservableGauge
	var floatGauge otelmetric.Float64ObservableGauge

	// gauges are asynchronous: they are updated in the callback when otel asks for it.
	if isInt {
		intGauge, err = meter.Int64ObservableGauge(gauge.Name)
		if err != nil {
			return nil, err
		}
	} else {
		floatGauge, err = meter.Float64ObservableGauge(gauge.Name)
		if err != nil {
			return nil, err
		}
	}

	callback := func(ctx context.Context, obs otelmetric.Observer) error {
		// This is a one-shot gadget, hence we can run it here and wait for it to finish
		// without having to create a new goroutine.
		if _, err = runtime.RunGadget(gadgetCtx); err != nil {
			return fmt.Errorf("running gadget: %w", err)
		}

		entries := <-entriesChan
		gauges, err := parser.AggregateEntries(gauge.Labels, entries, gauge.Field, isInt)
		if err != nil {
			return err
		}

		for _, gauge := range gauges {
			attrs := otelmetric.WithAttributes(gauge.Attrs...)
			if isInt {
				obs.ObserveInt64(intGauge, gauge.Int64Val, attrs)
			} else {
				obs.ObserveFloat64(floatGauge, gauge.Float64Val, attrs)
			}
		}

		return nil
	}
	if isInt {
		gauge.registration, err = meter.RegisterCallback(callback, intGauge)
		if err != nil {
			return nil, err
		}
	} else {
		gauge.registration, err = meter.RegisterCallback(callback, floatGauge)
		if err != nil {
			return nil, err
		}
	}

	return gauge, nil
}
