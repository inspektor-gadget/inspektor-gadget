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

//go:build linux

package ustack

import (
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	otelhost "go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	oteltimes "go.opentelemetry.io/ebpf-profiler/times"
	oteltracehandler "go.opentelemetry.io/ebpf-profiler/tracehandler"
	oteltracer "go.opentelemetry.io/ebpf-profiler/tracer"
	oteltracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ebpftypes "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/symbolizer"
)

func readUserStackMap(gadgetCtx operators.GadgetContext, userStackMap, buildIDMap *ebpf.Map, stackId uint32) (string, string, []symbolizer.StackItemQuery, error) {
	logger := gadgetCtx.Logger()

	stack := [ebpftypes.UserPerfMaxStackDepth]uint64{}
	err := userStackMap.Lookup(stackId, &stack)
	if err != nil {
		logger.Warnf("stack with ID %d is lost: %s", stackId, err.Error())
		return "", "", nil, nil
	}

	var addressesBuilder strings.Builder
	stackQueries := make([]symbolizer.StackItemQuery, 0, ebpftypes.UserPerfMaxStackDepth)
	for i, addr := range stack {
		if addr == 0 {
			break
		}
		stackQueries = append(stackQueries, symbolizer.StackItemQuery{Addr: addr})
		fmt.Fprintf(&addressesBuilder, "[%d]0x%016x; ", i, addr)
	}
	addressesStr := addressesBuilder.String()
	buildIDStr := ""

	// The buildIDMap is optional. Older gadgets won't have it.
	if buildIDMap != nil && buildIDMap.MaxEntries() > 0 {
		// struct bpf_stack_build_id is part of Linux UAPI:
		// https://github.com/torvalds/linux/blob/v6.14/include/uapi/linux/bpf.h#L1451
		type bpfStackBuildID struct {
			status     int32
			buildID    [unix.BPF_BUILD_ID_SIZE]uint8
			offsetOrIP uint64 // Union of offset and ip
		}
		const sizeOfBpfStackBuildID = 32
		// Static assert that the size of bpfStackBuildID is correct
		_ = func() {
			var x [1]struct{}
			var v bpfStackBuildID
			_ = x[unsafe.Sizeof(v)-sizeOfBpfStackBuildID]
		}
		buildIDBuf := [ebpftypes.UserPerfMaxStackDepth * sizeOfBpfStackBuildID]byte{}
		buildid := (*[ebpftypes.UserPerfMaxStackDepth]bpfStackBuildID)(unsafe.Pointer(&buildIDBuf[0]))
		errLookup := buildIDMap.Lookup(stackId, &buildIDBuf)

		var buildIDsBuilder strings.Builder
	buildid_iter:
		for i := 0; i < ebpftypes.UserPerfMaxStackDepth; i++ {
			if errLookup != nil {
				// The gadget didn't collect build ids
				// Gadgets can use --collect-build-id to enable collecting build ids
				break
			}
			if i >= len(stackQueries) {
				break
			}

			b := buildid[i]
			switch b.status {
			case unix.BPF_STACK_BUILD_ID_EMPTY:
				break buildid_iter
			case unix.BPF_STACK_BUILD_ID_VALID:
				fmt.Fprintf(&buildIDsBuilder, "[%d]", i)
				for _, byte := range b.buildID {
					fmt.Fprintf(&buildIDsBuilder, "%02x", byte)
				}
				fmt.Fprintf(&buildIDsBuilder, " +%x; ", b.offsetOrIP)
				stackQueries[i].ValidBuildID = true
				stackQueries[i].BuildID = b.buildID
				stackQueries[i].Offset = b.offsetOrIP
			case unix.BPF_STACK_BUILD_ID_IP:
				fmt.Fprintf(&buildIDsBuilder, "[%d]%x; ", i, b.offsetOrIP)
				stackQueries[i].IP = b.offsetOrIP
			}

		}
		buildIDStr = buildIDsBuilder.String()
	}

	return addressesStr, buildIDStr, stackQueries, nil
}

type traceReporter struct {
	reportTraceEvent func(t *libpf.Trace, meta *samples.TraceEventMeta) error
}

func (r traceReporter) ReportTraceEvent(t *libpf.Trace, meta *samples.TraceEventMeta) error {
	return r.reportTraceEvent(t, meta)
}

func startOtelEbpfProfiler(gadgetCtx operators.GadgetContext, someMap *ebpf.Map) error {
	logger := gadgetCtx.Logger()

	includeTracers, err := oteltracertypes.Parse("all")
	if err != nil {
		return fmt.Errorf("failed to parse the included tracers: %w", err)
	}

	monitorInterval := 2.0 * time.Second

	// Load the eBPF code and map definitions
	intervals := oteltimes.New(0, monitorInterval, 0)
	trc, err := oteltracer.NewTracer(gadgetCtx.Context(), &oteltracer.Config{
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
		UProbeLinks:            nil,
		LoadProbe:              true,
	})
	if err != nil {
		return fmt.Errorf("failed to load eBPF tracer: %w", err)
	}

	logger.Infof("Starting OpenTelemetry eBPF Profiler: %v", trc)

	// Inspect ELF files on request
	trc.StartPIDEventProcessor(gadgetCtx.Context())

	// Cleanup ebpf maps when a process terminates
	if err := trc.AttachSchedMonitor(); err != nil {
		return fmt.Errorf("failed to attach scheduler monitor: %w", err)
	}

	traceCh := make(chan *otelhost.Trace)
	if err := trc.StartMapMonitors(gadgetCtx.Context(), traceCh); err != nil {
		return fmt.Errorf("failed to start map monitors: %v", err)
	}

	var rep traceReporter
	rep.reportTraceEvent = func(t *libpf.Trace, meta *samples.TraceEventMeta) error {
		fmt.Printf("Trace event: %+v\n", t)
		for i, h := range t.Frames {
			v := h.Value()
			if v.SourceLine != 0 {
				fmt.Printf("  #%d: %s +0x%x\n    %s:%d\n",
					i, v.FunctionName, v.AddressOrLineno, v.SourceFile, v.SourceLine)
			} else {
				fmt.Printf("  #%d: %s +0x%x\n",
					i, v.FunctionName, v.AddressOrLineno)
			}
		}
		fmt.Printf("Trace meta: %+v\n", meta)
		return nil
	}

	_, err = oteltracehandler.Start(gadgetCtx.Context(), rep, trc.TraceProcessor(),
		traceCh, intervals, uint32(16*os.Getpagesize()))
	if err != nil {
		return fmt.Errorf("failed to start OpenTelemetry trace handler: %w", err)
	}

	progName := "uprobe__generic"
	kprobeUnwindNative := trc.GetEbpfProgram(progName)
	logger.Infof("%s: %v", progName, kprobeUnwindNative)
	gadgetCtx.SetVar("otel-ebpf-program", kprobeUnwindNative)
	return nil
}
