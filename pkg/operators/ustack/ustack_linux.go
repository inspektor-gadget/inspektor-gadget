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
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	oteltimes "go.opentelemetry.io/ebpf-profiler/times"
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

func startOtelEbpfProfiler(gadgetCtx operators.GadgetContext, someMap *ebpf.Map) error {
	logger := gadgetCtx.Logger()

	includeTracers, err := oteltracertypes.Parse("all")
	if err != nil {
		return fmt.Errorf("failed to parse the included tracers: %w", err)
	}

	monitorInterval := 5.0 * time.Second

	// Load the eBPF code and map definitions
	trc, err := oteltracer.NewTracer(gadgetCtx.Context(), &oteltracer.Config{
		Intervals:              oteltimes.New(0, monitorInterval, 0),
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

	return nil
}
