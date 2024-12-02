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
)

//go:wasmimport env getSyscallName
func getSyscallName(id uint32) uint64

//go:wasmimport env getSyscallDeclaration
func getSyscallDeclaration(name uint64, pointer uint64) uint32

// Keep in sync with pkg/operators/wasm/syscalls.go.
const (
	isPointerFlag = 1 << iota
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
	ptr := bufPtr(getSyscallName(uint32(id)))
	if ptr == 0 {
		return "", fmt.Errorf("getting syscall name for syscall id %d", id)
	}

	str := ptr.string()
	ptr.free()

	return str, nil
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
