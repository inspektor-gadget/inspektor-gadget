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

// getMap get an existing map.
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

	ebpfMap, ok := i.gadgetCtx.GetVar(mapName)
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

// mapLookup returns a handle to a value.
// Params:
// - stack[0]: Map handle
// - stack[1]: Key pointer
// - stack[2]: Value pointer
// Return value:
// - 1 on success, 0 on error
func (i *wasmOperatorInstance) mapLookup(ctx context.Context, m wapi.Module, stack []uint64) {
	mapHandle := wapi.DecodeU32(stack[0])
	keyPtr := stack[1]
	valuePtr := stack[2]

	ebpfMap, ok := getHandle[*ebpf.Map](i, mapHandle)
	if !ok {
		i.logger.Warnf("mapLookup: getting a map from map handle")
		stack[0] = 0
		return
	}

	key, err := bufFromStack(m, keyPtr)
	if err != nil {
		i.logger.Warnf("mapLookup: getting a buf for key pointer")
		stack[0] = 0
		return
	}

	value, err := bufFromStack(m, valuePtr)
	if err != nil {
		i.logger.Warnf("mapLookup: getting a buf for value pointer")
		stack[0] = 0
		return
	}

	err = ebpfMap.Lookup(key, value)
	if err != nil {
		i.logger.Warnf("mapLookup: getting value: %v", err)
		stack[0] = 0
		return
	}

	err = bufToStack(m, value, valuePtr)
	if err != nil {
		i.logger.Warnf("mapLookup: writing back value to stack: %v", err)
		stack[0] = 0
		return
	}

	stack[0] = 1
}

// mapUpdate update a value.
// Params:
// - stack[0]: Map handle
// - stack[1]: Key pointer
// - stack[2]: Value pointer
// - stack[3]: Flag to update the map
// Return value:
// - 1 on success, 0 on error
func (i *wasmOperatorInstance) mapUpdate(ctx context.Context, m wapi.Module, stack []uint64) {
	mapHandle := wapi.DecodeU32(stack[0])
	keyPtr := stack[1]
	valuePtr := stack[2]
// 	flag := stack[3]

	ebpfMap, ok := getHandle[*ebpf.Map](i, mapHandle)
	if !ok {
		i.logger.Warnf("mapUpdate: getting a map from map handle")
		stack[0] = 0
		return
	}

	key, err := bufFromStack(m, keyPtr)
	if err != nil {
		i.logger.Warnf("mapLookup: getting a buf for key pointer")
		stack[0] = 0
		return
	}

	value, err := bufFromStack(m, valuePtr)
	if err != nil {
		i.logger.Warnf("mapLookup: getting a buf for value pointer")
		stack[0] = 0
		return
	}

	err = ebpfMap.Put(key, value)
	if err != nil {
		i.logger.Warnf("mapUpdate: updating value: %v", err)
		stack[0] = 0
		return
	}
	stack[0] = 1
}

// mapDelete deletes a value.
// Params:
// - stack[0]: Map handle
// - stack[1]: Key pointer
// Return value:
// - 1 on success, 0 on error
func (i *wasmOperatorInstance) mapDelete(ctx context.Context, m wapi.Module, stack []uint64) {
	mapHandle := wapi.DecodeU32(stack[0])
	keyPtr := stack[1]

	ebpfMap, ok := getHandle[*ebpf.Map](i, mapHandle)
	if !ok {
		i.logger.Warnf("mapDelete: getting a map from map handle")
		stack[0] = 0
		return
	}

	key, err := bufFromStack(m, keyPtr)
	if err != nil {
		i.logger.Warnf("mapDelete: getting a buf for key pointer")
		stack[0] = 0
		return
	}

	err = ebpfMap.Delete(key)
	if err != nil {
		i.logger.Warnf("mapDelete: deleting value: %v", err)
		stack[0] = 0
		return
	}
	stack[0] = 1
}
