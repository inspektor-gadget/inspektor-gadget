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

	"github.com/cilium/ebpf"
	"github.com/tetratelabs/wazero"
	wapi "github.com/tetratelabs/wazero/api"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func (i *wasmOperatorInstance) addMapFuncs(env wazero.HostModuleBuilder) {
	exportFunction(env, "getMap", i.getMap,
		[]wapi.ValueType{wapi.ValueTypeI64}, // MapName
		[]wapi.ValueType{wapi.ValueTypeI32}, // Map
	)

	exportFunction(env, "mapLookup", i.mapLookup,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // Map
			wapi.ValueTypeI64, // Key pointer
			wapi.ValueTypeI64, // Value pointer
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Error
	)

	exportFunction(env, "mapUpdate", i.mapUpdate,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // Map
			wapi.ValueTypeI64, // Key pointer
			wapi.ValueTypeI64, // Value pointer
			wapi.ValueTypeI64, // Flag
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Error
	)

	exportFunction(env, "mapDelete", i.mapDelete,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // Map
			wapi.ValueTypeI64, // Key pointer
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Error
	)
}

// getMap gets an existing map.
// Params:
// - stack[0] is the name of the map (string encoded)
// Return value:
// - Map handle on success, 0 on error
func (i *wasmOperatorInstance) getMap(ctx context.Context, m wapi.Module, stack []uint64) {
	mapNamePtr := stack[0]

	mapName, err := stringFromStack(m, mapNamePtr)
	if err != nil {
		i.logger.Warnf("getMap: reading string from stack: %v", err)
		stack[0] = 0
		return
	}

	ebpfMap, ok := i.gadgetCtx.GetVar(operators.MAP_PREFIX + mapName)
	if !ok {
		i.logger.Warnf("get map: no map for name %q", mapName)
		stack[0] = 0
		return
	}

	ebpfMap, ok = ebpfMap.(*ebpf.Map)
	if !ok {
		i.logger.Warnf("get map: map is not an ebpf map")
		stack[0] = 0
		return
	}

	stack[0] = wapi.EncodeU32(i.addHandle(ebpfMap))
}

// mapLookup searches the map for a value corresponding to the given key.
// If one is found, the value pointer will be used to "return" this value.
// The WASM side ensures value is already a pointer.
// Params:
// - stack[0]: Map handle
// - stack[1]: Key pointer
// - stack[2]: Value pointer
// Return value:
// - 0 on success, 1 on error
func (i *wasmOperatorInstance) mapLookup(ctx context.Context, m wapi.Module, stack []uint64) {
	mapHandle := wapi.DecodeU32(stack[0])
	keyPtr := stack[1]
	valuePtr := stack[2]

	ebpfMap, ok := getHandle[*ebpf.Map](i, mapHandle)
	if !ok {
		stack[0] = 1
		return
	}

	key, err := bufFromStack(m, keyPtr)
	if err != nil {
		i.logger.Warnf("mapLookup: getting a buf for key pointer: %v", err)
		stack[0] = 1
		return
	}

	value, err := bufFromStack(m, valuePtr)
	if err != nil {
		i.logger.Warnf("mapLookup: getting a buf for value pointer: %v", err)
		stack[0] = 1
		return
	}

	err = ebpfMap.Lookup(key, value)
	if err != nil {
		i.logger.Warnf("mapLookup: getting value: %v", err)
		stack[0] = 1
		return
	}

	// WASM side ensured the value is a pointer, so we can write to it.
	err = bufToStack(m, value, valuePtr)
	if err != nil {
		i.logger.Warnf("mapLookup: writing back value to stack: %v", err)
		stack[0] = 1
		return
	}

	stack[0] = 0
}

// mapUpdate updates a value.
// Params:
// - stack[0]: Map handle
// - stack[1]: Key pointer
// - stack[2]: Value pointer
// - stack[3]: Flag to update the map
// Return value:
// - 0 on success, 1 on error
func (i *wasmOperatorInstance) mapUpdate(ctx context.Context, m wapi.Module, stack []uint64) {
	mapHandle := wapi.DecodeU32(stack[0])
	keyPtr := stack[1]
	valuePtr := stack[2]
	flags := stack[3]

	ebpfMap, ok := getHandle[*ebpf.Map](i, mapHandle)
	if !ok {
		stack[0] = 1
		return
	}

	key, err := bufFromStack(m, keyPtr)
	if err != nil {
		i.logger.Warnf("mapLookup: getting a buf for key pointer: %v", err)
		stack[0] = 1
		return
	}

	value, err := bufFromStack(m, valuePtr)
	if err != nil {
		i.logger.Warnf("mapLookup: getting a buf for value pointer: %v", err)
		stack[0] = 1
		return
	}

	err = ebpfMap.Update(key, value, ebpf.MapUpdateFlags(flags))
	if err != nil {
		i.logger.Warnf("mapUpdate: updating value: %v", err)
		stack[0] = 1
		return
	}
	stack[0] = 0
}

// mapDelete deletes a value.
// Params:
// - stack[0]: Map handle
// - stack[1]: Key pointer
// Return value:
// - 0 on success, 1 on error
func (i *wasmOperatorInstance) mapDelete(ctx context.Context, m wapi.Module, stack []uint64) {
	mapHandle := wapi.DecodeU32(stack[0])
	keyPtr := stack[1]

	ebpfMap, ok := getHandle[*ebpf.Map](i, mapHandle)
	if !ok {
		stack[0] = 1
		return
	}

	key, err := bufFromStack(m, keyPtr)
	if err != nil {
		i.logger.Warnf("mapDelete: getting a buf for key pointer: %v", err)
		stack[0] = 1
		return
	}

	err = ebpfMap.Delete(key)
	if err != nil {
		i.logger.Warnf("mapDelete: deleting value: %v", err)
		stack[0] = 1
		return
	}
	stack[0] = 0
}
