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
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ebpftypes "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/symbolizer"
)

// struct bpf_stack_build_id is part of Linux UAPI:
// https://github.com/torvalds/linux/blob/v6.14/include/uapi/linux/bpf.h#L1451
type bpfStackBuildID struct {
	Status     int32
	BuildID    [unix.BPF_BUILD_ID_SIZE]uint8
	OffsetOrIP uint64 // Union of offset and ip
}

func checkBuildIDMap(buildIDMap *ebpf.Map) error {
	expectedValueSize := uint32(ebpftypes.UserPerfMaxStackDepth * unsafe.Sizeof(bpfStackBuildID{}))
	if buildIDMap.ValueSize() != expectedValueSize {
		return fmt.Errorf("build id map has unexpected value size %d instead of %d",
			buildIDMap.ValueSize(), expectedValueSize)
	}

	return nil
}

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
		buildid := [ebpftypes.UserPerfMaxStackDepth]bpfStackBuildID{}
		errLookup := buildIDMap.Lookup(stackId, &buildid)
		if errLookup != nil {
			// The gadget didn't collect build ids
			// Gadgets can use --collect-build-id to enable collecting build ids
			return addressesStr, "", stackQueries, nil
		}

		var buildIDsBuilder strings.Builder
	buildid_iter:
		for i := 0; i < ebpftypes.UserPerfMaxStackDepth; i++ {
			if i >= len(stackQueries) {
				break
			}

			b := buildid[i]
			switch b.Status {
			case unix.BPF_STACK_BUILD_ID_EMPTY:
				break buildid_iter
			case unix.BPF_STACK_BUILD_ID_VALID:
				fmt.Fprintf(&buildIDsBuilder, "[%d]", i)
				for _, byte := range b.BuildID {
					fmt.Fprintf(&buildIDsBuilder, "%02x", byte)
				}
				fmt.Fprintf(&buildIDsBuilder, " +%x; ", b.OffsetOrIP)
				stackQueries[i].ValidBuildID = true
				stackQueries[i].BuildID = b.BuildID
				stackQueries[i].Offset = b.OffsetOrIP
			case unix.BPF_STACK_BUILD_ID_IP:
				fmt.Fprintf(&buildIDsBuilder, "[%d]%x; ", i, b.OffsetOrIP)
				stackQueries[i].IP = b.OffsetOrIP
			}

		}
		buildIDStr = buildIDsBuilder.String()
	}

	return addressesStr, buildIDStr, stackQueries, nil
}
