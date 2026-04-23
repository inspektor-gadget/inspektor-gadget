// Copyright 2026 The Inspektor Gadget authors
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
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	oteltimes "go.opentelemetry.io/ebpf-profiler/times"
	oteltracer "go.opentelemetry.io/ebpf-profiler/tracer"
	oteltracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
	"golang.org/x/sys/unix"

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
		waiters:        make(map[uint64]chan struct{}),
	}
	ctx := options.Context
	if ctx == nil {
		ctx = context.TODO()
	}
	if err := o.startOtelEbpfProfiler(ctx); err != nil {
		return nil, fmt.Errorf("starting OTel eBPF profiler: %w", err)
	}
	return o, nil
}

func (d *otelResolver) Priority() int {
	return 0
}

type otelResolverInstance struct {
	options symbolizer.SymbolizerOptions

	trc *oteltracer.Tracer

	// mu protects correlationMap and waiters. There is a single producer
	// (the traceReporter callback, called from the OTel map monitor
	// goroutine) but there can be multiple consumers: a gadget may have
	// several datasources (e.g. multiple eBPF ring buffers or hash maps),
	// each calling Resolve() concurrently on the same correlation ID.
	mu             sync.Mutex
	correlationMap map[uint64]libpf.Frames
	// waiters holds channels for Resolve() calls waiting on a correlation ID.
	// The channel is closed by traceReporter when the trace arrives.
	waiters map[uint64]chan struct{}
}

// correlationTimeout is how long Resolve() waits for an OTel stack trace
// to arrive for a given correlation ID.
//
// The OTel trace event monitor polls its perf ring buffer every 250ms
// (TracePollInterval in otel-ebpf-profiler/times). After reading the raw
// trace, HandleTrace() processes it: this includes symbolization of
// interpreted frames which may involve reading the target process memory
// (e.g. via process_vm_readv for Python frame objects). In practice, the
// end-to-end latency from BPF event to correlationMap insertion has been
// observed at ~130ms on average.
//
// The 800ms timeout provides sufficient headroom over the worst case
// (one full 250ms poll interval + processing time).
const correlationTimeout = 800 * time.Millisecond

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

func (o *otelResolverInstance) Resolve(task symbolizer.Task, stackQueries []symbolizer.StackItemQuery, stackResponses []symbolizer.StackItemResponse) ([]symbolizer.StackItemResponse, error) {
	log.Debugf("OtelResolverInstance.Resolve called for task %+v", task)
	if task.CorrelationID == 0 {
		return nil, nil
	}

	frames, ok := o.lookupOrWait(task.CorrelationID, task.EventBootTimestamp)
	if !ok {
		log.Warnf("OtelResolverInstance.Resolve: no frames found for correlation ID %d after timeout. Give up.", task.CorrelationID)
		return nil, nil
	}

	// Collect user (non-kernel) frames from the otel profiler.
	type userFrame struct {
		functionName string
	}
	var userFrames []userFrame
	for _, f := range frames {
		v := f.Value()
		if v.Type == libpf.KernelFrame {
			continue
		}
		userFrames = append(userFrames, userFrame{
			functionName: v.FunctionName.String(),
		})
	}

	log.Debugf("OtelResolverInstance.Resolve: otel has %d user frames, native stack has %d entries",
		len(userFrames), len(stackResponses))

	// The otel profiler captures the full interpreted stack (e.g., 20 Python
	// frames) while bpf_get_stackid only sees the native C stack (e.g., 2
	// CPython interpreter frames). When otel has more frames, build a new
	// response of the right size and return it as a replacement.
	result := stackResponses
	if len(userFrames) > len(stackResponses) {
		result = make([]symbolizer.StackItemResponse, len(userFrames))
	}

	for i, uf := range userFrames {
		if i >= len(result) {
			break
		}
		if uf.functionName != "" {
			result[i].Symbol = uf.functionName
			result[i].Found = true
			log.Debugf("OtelResolverInstance.Resolve: resolved frame %d: %s", i, uf.functionName)
		}
	}

	// Return non-nil replacement only if we built a new, larger slice.
	// This signals the orchestrator to use otel's stack and skip remaining
	// resolvers (native addresses don't correspond to these frames).
	if len(userFrames) > len(stackResponses) {
		return result, nil
	}
	return nil, nil
}

type traceReporter struct {
	reportTraceEvent func(t *libpf.Trace, meta *samples.TraceEventMeta) error
}

func (r traceReporter) ReportTraceEvent(t *libpf.Trace, meta *samples.TraceEventMeta) error {
	return r.reportTraceEvent(t, meta)
}

// lookupOrWait looks up the correlation ID in the map. If not found, it
// registers a waiter channel and blocks until the trace arrives or a
// timeout expires.
//
// If eventBootTimestamp is non-zero (from bpf_ktime_get_boot_ns in
// struct gadget_user_stack), the timeout is adaptive: it accounts for
// time already elapsed since the BPF event was produced. This prevents
// backlogged events from each waiting the full timeout, which would
// cause unbounded lag when OTel fails to unwind certain stacks.
// When eventBootTimestamp is zero (older gadgets without the field, or
// Linux < 5.8 where bpf_ktime_get_boot_ns is unavailable), the fixed
// correlationTimeout is used.
func (o *otelResolverInstance) lookupOrWait(correlationID uint64, eventBootTimestamp uint64) (libpf.Frames, bool) {
	o.mu.Lock()
	frames, ok := o.correlationMap[correlationID]
	if ok {
		o.mu.Unlock()
		return frames, true
	}

	// Register a waiter. If another Resolve() call from a different
	// datasource is already waiting for the same correlation ID, reuse
	// its channel so that close() wakes all waiters.
	ch, exists := o.waiters[correlationID]
	if !exists {
		ch = make(chan struct{})
		o.waiters[correlationID] = ch
	}
	o.mu.Unlock()

	timeout := correlationTimeout
	if eventBootTimestamp != 0 {
		// The timestamp comes from bpf_ktime_get_boot_ns() stored in
		// struct gadget_user_stack.boot_timestamp. Compare with
		// CLOCK_BOOTTIME which uses the same clock source.
		var ts unix.Timespec
		_ = unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts)
		nowBootNs := uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
		if nowBootNs < eventBootTimestamp {
			// Clock anomaly: skip waiting entirely.
			timeout = 0
			log.Debugf("OtelResolverInstance: clock anomaly for correlation ID %d: skipping wait", correlationID)
		} else {
			elapsed := time.Duration(nowBootNs - eventBootTimestamp)
			timeout = correlationTimeout - elapsed
			if timeout <= 0 {
				log.Debugf("OtelResolverInstance: correlation ID %d already past deadline (event age %v): skipping wait", correlationID, elapsed)
				timeout = 0
			} else {
				log.Debugf("OtelResolverInstance: waiting for correlation ID %d (elapsed %v, remaining timeout %v)", correlationID, elapsed, timeout)
			}
		}
	} else {
		log.Debugf("OtelResolverInstance: waiting for correlation ID %d (no boot timestamp, using fixed timeout %v)", correlationID, timeout)
	}

	if timeout > 0 {
		select {
		case <-ch:
			log.Debugf("OtelResolverInstance: correlation ID %d arrived after wait", correlationID)
		case <-time.After(timeout):
			log.Debugf("OtelResolverInstance: timeout waiting for correlation ID %d after %v", correlationID, timeout)
		}
	}

	// Clean up waiter if it's still ours (the traceReporter may have
	// already removed it by closing the channel).
	o.mu.Lock()
	if w, ok := o.waiters[correlationID]; ok && w == ch {
		delete(o.waiters, correlationID)
	}
	frames, ok = o.correlationMap[correlationID]
	o.mu.Unlock()
	return frames, ok
}

func bpfVerifierLogLevel() uint32 {
	if log.IsLevelEnabled(log.DebugLevel) {
		return 2 // full verifier log
	}
	return 0
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
		log.Debugf("Received OpenTelemetry trace (correlation ID %d, pid %d, tid %d):\n%s\n",
			meta.CorrelationID, meta.PID, meta.TID, stackStr)

		o.mu.Lock()
		o.correlationMap[meta.CorrelationID] = t.Frames
		if ch, ok := o.waiters[meta.CorrelationID]; ok {
			close(ch)
			delete(o.waiters, meta.CorrelationID)
		}
		o.mu.Unlock()
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
		VerboseMode:            log.IsLevelEnabled(log.DebugLevel),
		BPFVerifierLogLevel:    bpfVerifierLogLevel(),
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
