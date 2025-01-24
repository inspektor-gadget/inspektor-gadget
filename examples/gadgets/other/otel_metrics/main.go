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

package main

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	otelmetrics "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/otel-metrics"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

func do() error {
	var producer func()

	// We will simulate generating metrics for three nodes; these strings will serve as the only key for the metrics
	nodes := []string{"node1", "node2", "node3"}

	// used to stop the producer
	done := make(chan struct{})
	// used to wait for the producer to finish
	wg := &sync.WaitGroup{}

	metricsGenerator := simple.New("myHandler",
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			ds, err := gadgetCtx.RegisterDataSource(datasource.TypeSingle, "metrics")
			if err != nil {
				return err
			}
			ds.AddAnnotation(otelmetrics.AnnotationMetricsCollect, "true")

			// The node name will be used as key
			node, err := ds.AddField(
				"node",
				api.Kind_String,
				datasource.WithAnnotations(map[string]string{
					otelmetrics.AnnotationMetricsType:        otelmetrics.MetricTypeKey,
					otelmetrics.AnnotationMetricsDescription: "Node name",
				}),
			)
			if err != nil {
				return err
			}

			// Latency will be recorded as histogram
			latency, err := ds.AddField(
				"latency",
				api.Kind_Uint64,
				datasource.WithAnnotations(map[string]string{
					otelmetrics.AnnotationMetricsType:        otelmetrics.MetricTypeHistogram,
					otelmetrics.AnnotationMetricsDescription: "Latency",
				}),
			)
			if err != nil {
				return err
			}

			// Memory will be recorded as gauge
			mem, err := ds.AddField(
				"memory",
				api.Kind_Uint64,
				datasource.WithAnnotations(map[string]string{
					otelmetrics.AnnotationMetricsType:        otelmetrics.MetricTypeGauge,
					otelmetrics.AnnotationMetricsDescription: "Memory usage",
				}),
			)
			if err != nil {
				return err
			}

			// Every second the counter gets increased by 1
			ctr, err := ds.AddField(
				"ctr",
				api.Kind_Uint64,
				datasource.WithAnnotations(map[string]string{
					otelmetrics.AnnotationMetricsType:        otelmetrics.MetricTypeCounter,
					otelmetrics.AnnotationMetricsDescription: "Number of metric events",
				}),
			)
			if err != nil {
				return err
			}

			producer = func() {
				defer wg.Done()
				ticker := time.NewTicker(time.Second)
				for {
					select {
					case <-ticker.C:
						for _, n := range nodes {
							// emit new metrics
							metrics, err := ds.NewPacketSingle()
							if err != nil {
								gadgetCtx.Logger().Warnf("failed to create packet: %v", err)
								continue
							}

							node.PutString(metrics, n)

							latency.PutUint64(metrics, uint64(rand.Intn(2000)))

							var m runtime.MemStats
							runtime.ReadMemStats(&m)
							mem.PutUint64(metrics, m.TotalAlloc)

							ctr.PutUint64(metrics, 1)

							ds.EmitAndRelease(metrics)
						}
					case <-done:
						return
					}
				}
			}

			return nil
		}),
		simple.OnStart(func(gadgetCtx operators.GadgetContext) error {
			wg.Add(1)
			go producer()
			return nil
		}),
		simple.OnStop(func(gadgetCtx operators.GadgetContext) error {
			close(done)
			return nil
		}),
	)

	// Initialize operator with default settings
	globalParams := apihelpers.ToParamDescs(otelmetrics.Operator.GlobalParams()).ToParams()
	globalParams.Set(otelmetrics.ParamOtelMetricsListen, "true")
	otelmetrics.Operator.Init(globalParams)

	l := logger.DefaultLogger()
	l.SetLevel(logger.DebugLevel)

	gadgetCtx := gadgetcontext.New(
		context.Background(),
		"none",
		gadgetcontext.WithDataOperators(metricsGenerator, otelmetrics.Operator),
		gadgetcontext.WithLogger(l),
	)

	// Create the runtime
	runtime := local.New()
	if err := runtime.Init(nil); err != nil {
		return fmt.Errorf("runtime init: %w", err)
	}
	defer runtime.Close()

	params := map[string]string{
		"operator.otel-metrics.otel-metrics-name": "metrics",
	}

	// Run the gadget
	if err := runtime.RunGadget(gadgetCtx, nil, params); err != nil {
		return fmt.Errorf("running gadget: %w", err)
	}

	// Wait for the producer to finish
	wg.Wait()

	return nil
}

func main() {
	if err := do(); err != nil {
		fmt.Printf("Error running application: %s\n", err)
		os.Exit(1)
	}
}
