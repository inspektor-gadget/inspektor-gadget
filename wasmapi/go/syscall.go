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

package api

import (
	"fmt"
	"runtime"
	"unsafe"
	_ "unsafe"
)

//go:wasmimport env getSyscallName
//go:linkname getSyscallName getSyscallName
func getSyscallName(id uint32, dst uint64) uint32

//go:wasmimport env getSyscallID
//go:linkname getSyscallID getSyscallID
func getSyscallID(name uint64) int32

//go:wasmimport env getSyscallDeclaration
//go:linkname getSyscallDeclaration getSyscallDeclaration
func getSyscallDeclaration(name uint64, pointer uint64) uint32

// Keep in sync with pkg/operators/wasm/syscalls.go.
const (
	isPointerFlag    = 1 << iota
	maxSyscallLength = 64
)

// Keep in sync with pkg/operators/wasm/syscalls.go.
type syscallParam struct {
	name  [32]byte
	flags uint32
}

// Keep in sync with pkg/operators/wasm/syscalls.go.
type syscallDeclaration struct {
	name     [32]byte
	nrParams uint8
	_        [3]byte
	params   [6]syscallParam
}

type SyscallParam struct {
	Name      string
	IsPointer bool
}

type SyscallDeclaration struct {
	Name   string
	Params []SyscallParam
}

func GetSyscallName(id uint16) (string, error) {
	dst := make([]byte, maxSyscallLength)

	ret := getSyscallName(uint32(id), uint64(bytesToBufPtr(dst)))
	if ret == 1 {
		return "", fmt.Errorf("getting syscall name for syscall id %d", id)
	}
	return fromCString(dst), nil
}

func GetSyscallID(name string) (int32, error) {
	id := getSyscallID(uint64(stringToBufPtr(name)))
	if id == -1 {
		return 0, fmt.Errorf("getting syscall ID for syscall %s", name)
	}

	return id, nil
}

func GetSyscallDeclaration(name string) (SyscallDeclaration, error) {
	var decl syscallDeclaration

	// Create pointer to decl that will be filled by the host.
	unsafePtr := unsafe.Pointer(&decl)
	size := unsafe.Sizeof(decl)
	bufPtr := bufPtr(uint64(size)<<32 | uint64(uintptr(unsafePtr)))

	ret := getSyscallDeclaration(uint64(stringToBufPtr(name)), uint64(bufPtr))
	runtime.KeepAlive(name)
	runtime.KeepAlive(decl)
	if ret == 1 {
		return SyscallDeclaration{}, fmt.Errorf("syscall declaration %s not found", name)
	}

	declaration := SyscallDeclaration{
		Name:   fromCString(decl.name[:]),
		Params: make([]SyscallParam, decl.nrParams),
	}
	for i := range decl.nrParams {
		declaration.Params[i] = SyscallParam{
			Name:      fromCString(decl.params[i].name[:]),
			IsPointer: (decl.params[i].flags & isPointerFlag) != 0,
		}
	}

	return declaration, nil
}
