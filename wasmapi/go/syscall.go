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
	"errors"
	"fmt"
	"runtime"
)

//go:wasmimport env getSyscallName
func getSyscallName(id uint32) uint64

//go:wasmimport env getSyscallDeclaration
func getSyscallDeclaration(name uint64) uint32

//go:wasmimport env syscallDeclarationGetParameterCount
func syscallDeclarationGetParameterCount(s uint32) int32

//go:wasmimport env syscallDeclarationParamIsPointer
func syscallDeclarationParamIsPointer(s uint32, param uint32) uint32

//go:wasmimport env syscallDeclarationGetParameterName
func syscallDeclarationGetParameterName(s uint32, param uint32) uint64

type SyscallDeclaration uint32

func GetSyscallName(id uint16) (string, error) {
	ptr := bufPtr(getSyscallName(uint32(id)))
	if ptr == 0 {
		return "", fmt.Errorf("getting syscall name for syscall id %d", id)
	}

	return ptr.string(), nil
}

func GetSyscallDeclaration(name string) (SyscallDeclaration, error) {
	ret := getSyscallDeclaration(uint64(stringToBufPtr(name)))
	runtime.KeepAlive(name)
	if ret == 0 {
		return 0, fmt.Errorf("syscall declaration %s not found", name)
	}
	return SyscallDeclaration(ret), nil
}

func (s SyscallDeclaration) GetParameterCount() (uint32, error) {
	ret := syscallDeclarationGetParameterCount(uint32(s))
	if ret == -1 {
		return 0, errors.New("getting syscall number of parameters")
	}
	return uint32(ret), nil
}

func (s SyscallDeclaration) ParamIsPointer(paramNumber uint32) (bool, error) {
	ret := syscallDeclarationParamIsPointer(uint32(s), paramNumber)
	switch ret {
	case 0:
		return false, fmt.Errorf("checking whether syscall param number %d is a pointer", paramNumber)
	case 1:
		return true, nil
	case 2:
		return false, nil
	default:
		return false, fmt.Errorf("get %d returned, expected 0, 1 or 2", ret)
	}
}

func (s SyscallDeclaration) GetParameterName(paramNumber uint32) (string, error) {
	ptr := bufPtr(syscallDeclarationGetParameterName(uint32(s), paramNumber))
	if ptr == 0 {
		return "", fmt.Errorf("getting syscall param number %d name", paramNumber)
	}

	return ptr.string(), nil
}
