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

	"github.com/cilium/ebpf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ebpftypes "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/symbolizer"
)

func readUserStackMap(gadgetCtx operators.GadgetContext, userStackMap *ebpf.Map, stackId uint32) (string, []symbolizer.StackItemQuery, error) {
	logger := gadgetCtx.Logger()

	stack := [ebpftypes.UserPerfMaxStackDepth]uint64{}
	err := userStackMap.Lookup(stackId, &stack)
	if err != nil {
		logger.Warnf("stack with ID %d is lost: %s", stackId, err.Error())
		return "", nil, nil
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

	return addressesStr, stackQueries, nil
}
