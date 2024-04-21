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

	wapi "github.com/tetratelabs/wazero/api"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
)

func (i *wasmOperatorInstance) fieldAccessorGetString(ctx context.Context, m wapi.Module, stack []uint64) {
	acc, ok := i.getFromMemMap(wapi.DecodeU32(stack[0])).(datasource.FieldAccessor)
	if !ok {
		stack[0] = 0
		i.gadgetCtx.Logger().Warnf("accessor not present")
		return
	}
	data, ok := i.getFromMemMap(wapi.DecodeU32(stack[1])).(datasource.Data)
	if !ok {
		stack[0] = 0
		i.gadgetCtx.Logger().Warnf("data not present")
		return
	}

	str := []byte(acc.String(data))

	malloc := m.ExportedFunction("malloc")
	res, err := malloc.Call(ctx, uint64(len(str)))
	if err != nil {
		i.gadgetCtx.Logger().Warnf("malloc failed: %v", err)
		stack[0] = 0
		return
	}

	if !m.Memory().Write(uint32(res[0]), str) {
		// log.Panicf("out of range of memory size")
		stack[0] = 0
		return
	}

	stack[0] = uint64(len(str))<<32 | uint64(res[0])
}

func (i *wasmOperatorInstance) fieldAccessorSetString(ctx context.Context, m wapi.Module, stack []uint64) {
	acc, ok := i.getFromMemMap(wapi.DecodeU32(stack[0])).(datasource.FieldAccessor)
	if !ok {
		stack[0] = 0
		i.gadgetCtx.Logger().Warnf("accessor not present")
		return
	}
	data, ok := i.getFromMemMap(wapi.DecodeU32(stack[1])).(datasource.Data)
	if !ok {
		stack[0] = 0
		i.gadgetCtx.Logger().Warnf("data not present")
		return
	}

	str, err := stringFromStack(m, stack, 2)
	if err == nil {
		acc.Set(data, []byte(str))
	}
}
