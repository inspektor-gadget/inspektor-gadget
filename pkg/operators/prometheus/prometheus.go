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
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/prometheus/config"
)

type PrometheusProvider interface {
	GetPrometheusConfig() *config.Config
	SetMetricsProvider(metric.MeterProvider)
}

const (
	// ParamEnableMetrics = "enable-metrics"
	ParamListenAddress = "metrics-listen-address"
	ParamMetricsPath   = "metrics-path"
	// keep aligned with values in pkg/resources/manifests/deploy.yaml
	DefaultListenAddr  = "0.0.0.0:2223"
	DefaultMetricsPath = "/metrics"
)

type Prometheus struct {
	exporter      *prometheus.Exporter
	meterProvider metric.MeterProvider
	bucketConfigs map[string]*BucketConfig
}

func (p *Prometheus) EnrichEvent(a any) error {
	return nil
}

func (p *Prometheus) Name() string {
	return "Prometheus"
}

func (p *Prometheus) Description() string {
	return "Provides a facility to export metrics using Prometheus"
}

func (p *Prometheus) Dependencies() []string {
	return nil
}

func (p *Prometheus) GlobalParamDescs() params.ParamDescs {
	return params.ParamDescs{
		// TODO: this should be a deploy time flag
		// {
		//	Key:          ParamEnableMetrics,
		//	Title:        "Enable Prometheus metrics",
		//	DefaultValue: "false",
		//	Description:  "Enables exporting prometheus metrics",
		//	TypeHint:     params.TypeBool,
		// },
		// TODO: find a way to expose this to ig-k8s users
		{
			Key:          ParamListenAddress,
			Title:        "Listen address",
			DefaultValue: DefaultListenAddr,
			Description:  "Address to serve prometheus metrics on",
		},
		{
			Key:          ParamMetricsPath,
			Title:        "Metrics path",
			DefaultValue: DefaultMetricsPath,
			Description:  "Path to export prometheus metrics on",
		},
	}
}

func (p *Prometheus) ParamDescs() params.ParamDescs {
	return nil
}

func (p *Prometheus) Init(globalParams *params.Params) error {
	// if !globalParams.Get(ParamEnableMetrics).AsBool() {
	//	return nil
	// }
	log.Printf("init prom")

	exporter, err := prometheus.New()
	if err != nil {
		return fmt.Errorf("initialize prometheus exporter: %w", err)
	}
	p.exporter = exporter
	p.meterProvider = sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter), sdkmetric.WithView(p.histogramViewFunc()))

	listenAddress := globalParams.Get(ParamListenAddress).AsString()
	metricsPath := globalParams.Get(ParamMetricsPath).AsString()

	go func() {
		mux := http.NewServeMux()
		mux.Handle(metricsPath, promhttp.Handler())
		err := http.ListenAndServe(listenAddress, mux)
		if err != nil {
			log.Errorf("serving http: %s", err)
			return
		}
	}()
	return nil
}

func (p *Prometheus) CanOperateOn(gadget gadgets.GadgetDesc) bool {
	inst, ok := gadget.(gadgets.GadgetInstantiate)
	if !ok {
		return false
	}
	tempInstance, err := inst.NewInstance()
	if err != nil {
		return false
	}
	if _, ok := tempInstance.(PrometheusProvider); !ok {
		return false
	}
	return true
}

func (p *Prometheus) Close() error {
	return nil
}

func (p *Prometheus) Instantiate(gadgetCtx operators.GadgetContext, gadgetInstance any, params *params.Params) (operators.OperatorInstance, error) {
	if provider, ok := gadgetInstance.(PrometheusProvider); ok {
		provider.SetMetricsProvider(p.meterProvider)
		p.bucketConfigs = bucketConfigsFromConfig(provider.GetPrometheusConfig())
	}
	return p, nil
}

func (p *Prometheus) PreGadgetRun() error {
	return nil
}

func (p *Prometheus) PostGadgetRun() error {
	return nil
}

func init() {
	operators.Register(&Prometheus{})
}
