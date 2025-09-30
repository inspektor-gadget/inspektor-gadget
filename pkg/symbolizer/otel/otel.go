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

package otel

import (
	"context"
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	oteltimes "go.opentelemetry.io/ebpf-profiler/times"
	oteltracer "go.opentelemetry.io/ebpf-profiler/tracer"
	oteltracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/symbolizer"
)

func init() {
	symbolizer.RegisterResolver(&otelResolver{})
}

type otelResolver struct{}

func (d *otelResolver) NewInstance(options symbolizer.SymbolizerOptions) (symbolizer.ResolverInstance, error) {
	if !options.UseOtelEbpfProfiler {
		return nil, nil
	}

	o := &otelResolverInstance{
		options:        options,
		correlationMap: make(map[uint64]libpf.Frames),
	}
	o.startOtelEbpfProfiler(context.TODO())
	return o, nil
}

func (d *otelResolver) Priority() int {
	return 0
}

type otelResolverInstance struct {
	options symbolizer.SymbolizerOptions

	trc            *oteltracer.Tracer
	correlationMap map[uint64]libpf.Frames
}

func (o *otelResolverInstance) IsPruningNeeded() bool {
	return false
}

func (o *otelResolverInstance) PruneOldObjects(now time.Time, ttl time.Duration) {
}

func (o *otelResolverInstance) GetEbpfReplacements() map[string]interface{} {
	if o.trc == nil {
		return nil
	}
	return map[string]interface{}{
		symbolizer.OtelEbpfProgramKprobe:    o.trc.GetProbeEntryEbpfProgram(),
		symbolizer.OtelGenericParamsMapName: o.trc.GetGenericParamsEbpfMap(),
	}
}

func (o *otelResolverInstance) Resolve(task symbolizer.Task, stackQueries []symbolizer.StackItemQuery, stackResponses []symbolizer.StackItemResponse) error {
	log.Debugf("OtelResolverInstance.Resolve called for task %+v", task)
	if task.CorrelationID == 0 {
		return nil
	}
	if task.CorrelationID == 0 {
		return nil
	}
	frames, ok := o.correlationMap[task.CorrelationID]
	if !ok {
		log.Debugf("OtelResolverInstance.Resolve: no frames found for correlation ID %d, waiting a bit", task.CorrelationID)
		// Hack: the otel trace comes from a separate path
		time.Sleep(time.Second)
		frames, ok = o.correlationMap[task.CorrelationID]
	}
	if !ok {
		log.Debugf("OtelResolverInstance.Resolve: still no frames found for correlation ID %d. Give up.", task.CorrelationID)
		return nil
	}
	userFrameIdx := 0
	for _, f := range frames {
		v := f.Value()
		if v.Type == libpf.KernelFrame {
			continue
		}
		if userFrameIdx >= len(stackResponses) {
			break
		}
		if v.FunctionName.String() != "" {
			// TODO: add other fields:
			// v.AddressOrLineno, v.SourceFile, v.SourceLine
			stackResponses[userFrameIdx].Symbol = v.FunctionName.String()
			stackResponses[userFrameIdx].Found = true

			fmt.Printf("OtelResolverInstance.Resolve: resolved frame %d:\n%s\n", userFrameIdx, v.FunctionName.String())
		}
		userFrameIdx++
	}

	return nil
}

type traceReporter struct {
	reportTraceEvent func(t *libpf.Trace, meta *samples.TraceEventMeta) error
}

func (r traceReporter) ReportTraceEvent(t *libpf.Trace, meta *samples.TraceEventMeta) error {
	return r.reportTraceEvent(t, meta)
}

func (o *otelResolverInstance) startOtelEbpfProfiler(ctx context.Context) error {
	includeTracers, err := oteltracertypes.Parse("all")
	if err != nil {
		return fmt.Errorf("parsing list of OpenTelemetry tracers: %w", err)
	}

	monitorInterval := 2.0 * time.Second

	var rep traceReporter
	rep.reportTraceEvent = func(t *libpf.Trace, meta *samples.TraceEventMeta) error {
		log.Debugf("traceReporter.reportTraceEvent called for trace %+v and meta %+v", t, meta)
		var stackBuilder strings.Builder
		for i, h := range t.Frames {
			v := h.Value()
			if v.SourceLine != 0 {
				stackBuilder.WriteString(fmt.Sprintf("  #%d: %s +0x%x\n    %s:%d\n",
					i, v.FunctionName, v.AddressOrLineno, v.SourceFile, v.SourceLine))
			} else {
				stackBuilder.WriteString(fmt.Sprintf("  #%d: %s +0x%x\n",
					i, v.FunctionName, v.AddressOrLineno))
			}
		}
		stackStr := stackBuilder.String()
		fmt.Printf("Received OpenTelemetry trace (correlation ID %d, pid %d, tid %d):\n%s\n",
			meta.CorrelationID, meta.PID, meta.TID, stackStr)

		o.correlationMap[meta.CorrelationID] = t.Frames
		return nil
	}

	// Load the eBPF code and map definitions
	intervals := oteltimes.New(0, monitorInterval, 0)
	trc, err := oteltracer.NewTracer(ctx, &oteltracer.Config{
		Intervals:              intervals,
		IncludeTracers:         includeTracers,
		FilterErrorFrames:      true,
		SamplesPerSecond:       0,
		MapScaleFactor:         0,
		KernelVersionCheck:     false,
		VerboseMode:            true,
		BPFVerifierLogLevel:    2, // 0=none, 1=basic, 2=full
		ProbabilisticInterval:  0,
		ProbabilisticThreshold: 0,
		OffCPUThreshold:        0,
		IncludeEnvVars:         nil,
		ProbeLinks:             nil,
		LoadProbe:              true,
		TraceReporter:          rep,
	})
	if err != nil {
		return fmt.Errorf("loading OpenTelemetry eBPF tracer: %w", err)
	}
	o.trc = trc

	log.Infof("Starting OpenTelemetry eBPF Profiler: %v", trc)

	// Inspect ELF files on request
	trc.StartPIDEventProcessor(ctx)

	// Cleanup ebpf maps when a process terminates
	if err := trc.AttachSchedMonitor(); err != nil {
		return fmt.Errorf("attaching scheduler monitor: %w", err)
	}

	traceCh := make(chan *libpf.EbpfTrace)
	if err := trc.StartMapMonitors(ctx, traceCh); err != nil {
		return fmt.Errorf("starting map monitors: %w", err)
	}

	go func() {
		// Poll the output channels
		for {
			select {
			case trace := <-traceCh:
				if trace != nil {
					trc.HandleTrace(trace)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return nil
}
