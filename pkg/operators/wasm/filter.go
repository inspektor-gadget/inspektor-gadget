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

package wasm

import (
	"context"

	"github.com/tetratelabs/wazero"
	wapi "github.com/tetratelabs/wazero/api"
)

func (i *wasmOperatorInstance) addFilterFuncs(env wazero.HostModuleBuilder) {
	exportFunction(env, "shouldDiscardMntnsID", i.shouldDiscardMntnsID,
		[]wapi.ValueType{
			wapi.ValueTypeI64, // MntNS ID
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Discard the event, 1 if true, 0 if false
	)
}

// shouldDiscardMntnsID returns 1 if the mount ns ID should be filtered out.
// Params:
// - stack[0]: mount ns ID
// Return value:
// - 1 if the mount ns ID should be filter out, 0 otherwise
func (i *wasmOperatorInstance) shouldDiscardMntnsID(ctx context.Context, m wapi.Module, stack []uint64) {
	// if the filtering map is not configured, we assume the gadget wants to get
	// all data
	if i.mntNsIDMap == nil {
		stack[0] = 0
		return
	}

	ret := uint32(0)

	mntnsID := uint64(stack[0])
	if err := i.mntNsIDMap.Lookup(mntnsID, &ret); err != nil {
		stack[0] = 1
		return
	}

	stack[0] = 0
}
