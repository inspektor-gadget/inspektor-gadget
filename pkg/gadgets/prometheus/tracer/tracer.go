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

//go:build !withoutebpf

package tracer

import (
	"go.opentelemetry.io/otel/metric"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	igprometheus "github.com/inspektor-gadget/inspektor-gadget/pkg/prometheus"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/prometheus/config"
)

type Tracer struct {
	meterProvider metric.MeterProvider
	config        *config.Config
}

func (t *Tracer) Init(gadgetCtx gadgets.GadgetContext) error {
	params := gadgetCtx.GadgetParams()
	metricsConfig := params.Get(ParamConfig).AsBytes()

	config, err := config.ParseConfig(metricsConfig)
	if err != nil {
		return err
	}
	t.config = config
	return nil
}

func (t *Tracer) Close() {
}

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	ctx := gadgetCtx.Context()
	gadgetCtx.Logger().Debugf("config: %+v", t.config)

	cleanup, err := igprometheus.CreateMetrics(ctx, t.config, t.meterProvider)
	if err != nil {
		return err
	}
	defer cleanup()

	gadgetCtx.Logger().Info("Publishing metrics...")

	<-ctx.Done()

	return nil
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	return &Tracer{}, nil
}

func (t *Tracer) SetMetricsProvider(meter metric.MeterProvider) {
	t.meterProvider = meter
}

func (t *Tracer) GetPrometheusConfig() *config.Config {
	return t.config
}
