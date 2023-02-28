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
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

type SetMetricsExporter interface {
	SetMetricsExporter(metric.Meter)
}

const (
	ParamEnableMetrics = "enable-metrics"
	ParamMetricsID     = "metrics-id"
	ParamListenAddress = "metrics-listen-address"
	ParamMetricsPath   = "metrics-path"
)

type Prometheus struct {
	exporter      *prometheus.Exporter
	meterProvider metric.MeterProvider
}

func (l *Prometheus) EnrichEvent(a any) error {
	return nil
}

func (l *Prometheus) Name() string {
	return "Prometheus"
}

func (l *Prometheus) Description() string {
	return "Provides a facility to export metrics using Prometheus"
}

func (l *Prometheus) Dependencies() []string {
	return nil
}

func (l *Prometheus) GlobalParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:          ParamListenAddress,
			DefaultValue: "127.0.0.1:2223",
			Description:  "Address to serve prometheus metrics on",
		},
		{
			Key:          ParamMetricsPath,
			DefaultValue: "/metrics",
			Description:  "Path to export prometheus metrics on",
		},
	}
}

func (l *Prometheus) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:          ParamEnableMetrics,
			Title:        "Enable metrics export",
			DefaultValue: "false",
			Description:  "Enables collecting metrics from the gadget and export it via Prometheus",
			IsMandatory:  true,
			TypeHint:     params.TypeBool,
		},
		{
			Key:         ParamMetricsID,
			Title:       "Metrics Identifier",
			Description: "Will be used as part of the scope name for the metrics",
		},
	}
}

func (l *Prometheus) Init(globalParams *params.Params) error {
	exporter, err := prometheus.New()
	if err != nil {
		return fmt.Errorf("initialize prometheus exporter: %w", err)
	}
	l.exporter = exporter
	l.meterProvider = sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))

	listenAddress := globalParams.Get(ParamListenAddress).AsString()
	metricsPath := globalParams.Get(ParamMetricsPath).AsString()

	go func() {
		mux := http.NewServeMux()
		mux.Handle(metricsPath, promhttp.Handler())
		err := http.ListenAndServe(listenAddress, mux)
		if err != nil {
			fmt.Printf("error serving http: %v", err)
			return
		}
	}()
	return nil
}

func (l *Prometheus) CanOperateOn(gadget gadgets.GadgetDesc) bool {
	inst, ok := gadget.(gadgets.GadgetInstantiate)
	if !ok {
		return false
	}
	tempInstance, err := inst.NewInstance()
	if err != nil {
		return false
	}
	_, ok = tempInstance.(SetMetricsExporter)
	return ok
}

func (l *Prometheus) Close() error {
	return nil
}

func (l *Prometheus) Instantiate(gadgetCtx operators.GadgetContext, gadgetInstance any, params *params.Params) (operators.OperatorInstance, error) {
	if !params.Get(ParamEnableMetrics).AsBool() {
		return l, nil
	}
	if setter, ok := gadgetInstance.(SetMetricsExporter); ok {
		id := params.Get(ParamMetricsID).AsString()
		if id == "" {
			id = gadgetCtx.ID()
		}
		meter := l.meterProvider.Meter(fmt.Sprintf("gadgets.inspektor-gadget.io/%s/%s/%s", gadgetCtx.GadgetDesc().Category(), gadgetCtx.GadgetDesc().Name(), id))
		setter.SetMetricsExporter(meter)
	}
	return l, nil
}

func (l *Prometheus) PreGadgetRun() error {
	return nil
}

func (l *Prometheus) PostGadgetRun() error {
	return nil
}

func init() {
	operators.Register(&Prometheus{})
}
