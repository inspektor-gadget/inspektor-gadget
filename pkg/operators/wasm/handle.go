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

package wasm

import (
	"context"

	"github.com/tetratelabs/wazero"
	wapi "github.com/tetratelabs/wazero/api"
)

func (i *wasmOperatorInstance) addHandleFuncs(env wazero.HostModuleBuilder) {
	exportFunction(env, "releaseHandle", i.releaseHandle,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // Handle
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Error
	)
}

// releaseHandle releases the handle of the object
// Params:
// - stack[0]: handle
// Return value:
// - 0 on success, 1 on error
func (i *wasmOperatorInstance) releaseHandle(ctx context.Context, m wapi.Module, stack []uint64) {
	mapHandle := wapi.DecodeU32(stack[0])

	_, ok := getHandle[any](i, mapHandle)
	if !ok {
		stack[0] = 1
		return
	}
	i.delHandle(mapHandle)
	stack[0] = 0
}
