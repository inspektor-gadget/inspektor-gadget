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
	"encoding/binary"
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

func (i *wasmOperatorInstance) writeErrToGuest(ctx context.Context, err uint32, addr uint32) {
	if addr == 0 {
		return
	}

	buf := make([]byte, 4)
	binary.NativeEndian.PutUint32(buf, err)
	if !i.mod.Memory().Write(addr, buf) {
		i.logger.Errorf("writing error bytes to guest memory: out of memory write")
		i.mod.CloseWithExitCode(ctx, 1)
	}
}

func (i *wasmOperatorInstance) writeToDstBuffer(src []byte, dstBuf uint64) error {
	if getLength(dstBuf) < uint32(len(src)) {
		return fmt.Errorf("writing %d bytes to guest memory buffer of %d bytes: not enough memory", len(src), getLength(dstBuf))
	}
	if !i.mod.Memory().Write(getAddress(dstBuf), src) {
		return fmt.Errorf("writing bytes to guest memory: out of memory write")
	}
	return nil
}

func isDataArrayHandle(handle uint32) bool {
	return handle&dataArrayHandleFlag != 0
}

func getIndexFromDataArrayHandle(dataHandle uint32) int {
	return int(dataHandle &^ dataArrayHandleFlag >> 16)
}
