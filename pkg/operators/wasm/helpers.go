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
	"errors"
	"fmt"

	"github.com/tetratelabs/wazero"
	wapi "github.com/tetratelabs/wazero/api"
)

func getLength(pointer uint64) uint32 {
	return uint32(pointer >> 32)
}

func getAddress(pointer uint64) uint32 {
	return uint32(pointer & 0xFFFFFFFF)
}

func bufFromStack(m wapi.Module, pointer uint64) ([]byte, error) {
	size := getLength(pointer)
	address := getAddress(pointer)
	buf, ok := m.Memory().Read(address, size)
	if !ok {
		return nil, errors.New("invalid pointer")
	}
	return buf, nil
}

func bufToStack(m wapi.Module, buf []byte, pointer uint64) error {
	address := getAddress(pointer)
	size := getLength(pointer)
	length := uint32(len(buf))

	if length > size {
		return fmt.Errorf("buffer size %d is bigger than %d", length, size)
	}

	if !m.Memory().Write(address, buf) {
		return fmt.Errorf("writing at address %x", address)
	}

	return nil
}

func stringFromStack(m wapi.Module, val uint64) (string, error) {
	// handle empty strings in a special way
	if val == 0 {
		return "", nil
	}

	buf, err := bufFromStack(m, val)
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

func exportFunction(
	env wazero.HostModuleBuilder,
	name string,
	fn func(ctx context.Context, m wapi.Module, stack []uint64),
	params, results []wapi.ValueType,
) {
	env.NewFunctionBuilder().
		WithGoModuleFunction(wapi.GoModuleFunc(fn), params, results).
		Export(name)
}

func (i *wasmOperatorInstance) writeToGuestMemory(ctx context.Context, buf []byte) (uint64, error) {
	res, err := i.guestMalloc.Call(ctx, uint64(len(buf)))
	if err != nil {
		return 0, fmt.Errorf("malloc failed: %w", err)
	}

	if !i.mod.Memory().Write(uint32(res[0]), buf) {
		return 0, fmt.Errorf("out of memory write")
	}

	return uint64(len(buf))<<32 | uint64(res[0]), nil
}

func isDataArrayHandle(handle uint32) bool {
	return handle&dataArrayHandleFlag != 0
}

func getIndexFromDataArrayHandle(dataHandle uint32) int {
	return int(dataHandle &^ dataArrayHandleFlag >> 16)
}
