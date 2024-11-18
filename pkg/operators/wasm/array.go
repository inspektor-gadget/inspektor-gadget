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

func (i *wasmOperatorInstance) addArrayFuncs(env wazero.HostModuleBuilder) {
	exportFunction(env, "arrayNew", i.arrayNew,
		[]wapi.ValueType{},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Array handle
	)

	exportFunction(env, "arrayLen", i.arrayLen,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // Array
		},
		[]wapi.ValueType{wapi.ValueTypeI64}, // Array length or error
	)

	exportFunction(env, "arrayGet", i.arrayGet,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // Array
			wapi.ValueTypeI32, // Index
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Handle or error
	)

	exportFunction(env, "arrayAppend", i.arrayAppend,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // Array
			wapi.ValueTypeI32, // Handle
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Error
	)
}

// arrayNew creates a new array of handle.
// Return value:
// - Array handle
func (i *wasmOperatorInstance) arrayNew(ctx context.Context, m wapi.Module, stack []uint64) {
	array := make([]uint32, 0)

	stack[0] = wapi.EncodeU32(i.addHandle(array))
}

// arrayLen returns the array length.
// Params:
// - stack[0]: Array handle
// Return value:
// - Array length on success, -1 on error
func (i *wasmOperatorInstance) arrayLen(ctx context.Context, m wapi.Module, stack []uint64) {
	arrayHandle := wapi.DecodeU32(stack[0])

	array, ok := getHandle[[]uint32](i, arrayHandle)
	if !ok {
		i.logger.Warnf("arrayLen: getting array handle")
		stack[0] = 0x100000000
		return
	}

	stack[0] = wapi.EncodeI64(int64(len(array)))
}

// arrayGet returns the handle at the given index.
// Params:
// - stack[0]: Array handle
// - stack[1]: Array index
// Return value:
// - Handle on success, 0 on error
func (i *wasmOperatorInstance) arrayGet(ctx context.Context, m wapi.Module, stack []uint64) {
	arrayHandle := wapi.DecodeU32(stack[0])
	idx := wapi.DecodeU32(stack[1])

	array, ok := getHandle[[]uint32](i, arrayHandle)
	if !ok {
		i.logger.Warnf("arrayGet: getting array handle")
		stack[0] = 0
		return
	}

	if idx >= uint32(len(array)) {
		i.logger.Warnf("arrayGet: index %d is greater or equal to array length %d", idx, len(array))
		stack[0] = 0
		return
	}

	stack[0] = wapi.EncodeU32(array[idx])
}

// arrayAppend appends the handle at the array end.
// Params:
// - stack[0]: Array handle
// - stack[1]: Handle
// Return value:
// - 0 on success, 1 on error
func (i *wasmOperatorInstance) arrayAppend(ctx context.Context, m wapi.Module, stack []uint64) {
	arrayHandle := wapi.DecodeU32(stack[0])
	handle := wapi.DecodeU32(stack[1])

	array, ok := getHandle[[]uint32](i, arrayHandle)
	if !ok {
		i.logger.Warnf("arrayAppend: getting array handle")
		stack[0] = 1
		return
	}

	array = append(array, handle)

	err := i.updateHandle(arrayHandle, array)
	if err != nil {
		i.logger.Warnf("arrayAppend: updating array handle: %v", err)
		stack[0] = 1
		return
	}

	stack[0] = 0
}
