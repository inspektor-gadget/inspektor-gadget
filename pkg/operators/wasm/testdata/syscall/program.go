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

package main

import (
	"fmt"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

const (
	unknownSyscallID  = uint16(1337)
	openTreeSyscallID = uint16(428)
)

//export gadgetInit
func gadgetInit() int {
	syscallID := unknownSyscallID
	syscallName, err := api.GetSyscallName(syscallID)
	if err != nil {
		api.Errorf("%v", err)
		return 1
	}

	// Check behavior is conform with strace.
	expectedSyscallName := fmt.Sprintf("syscall_%x", syscallID)
	if syscallName != expectedSyscallName {
		api.Errorf("mismatch for syscall %d: expected %q, got %q", syscallID, expectedSyscallName, syscallName)
		return 1
	}

	syscallID = openTreeSyscallID
	syscallName, err = api.GetSyscallName(syscallID)
	if err != nil {
		api.Errorf("%v", err)
		return 1
	}

	// open_tree has the same ID for both amd64 and arm64.
	expectedSyscallName = "open_tree"
	if syscallName != expectedSyscallName {
		api.Errorf("mismatch for syscall %d: expected %q, got %q", syscallID, expectedSyscallName, syscallName)
		return 1
	}

	syscallName = "foobar"
	declaration, err := api.GetSyscallDeclaration(syscallName)
	if err == nil {
		api.Errorf("expected no declaration for syscall %q, got %v", syscallName, declaration)
		return 1
	}

	syscallName = "execve"
	declaration, err = api.GetSyscallDeclaration(syscallName)
	if err != nil {
		api.Errorf("%v", err)
		return 1
	}

	paramCount := len(declaration.Params)
	expectedParamCount := 3
	if paramCount != expectedParamCount {
		api.Errorf("syscall %q has %d parameters, got %d", syscallName, expectedParamCount, paramCount)
		return 1
	}

	paramName := string(declaration.Params[0].Name)
	expectedParamName := "filename"
	if paramName != expectedParamName {
		api.Errorf("syscall %q, first parameter is named %q, got %q", syscallName, expectedParamName, paramName)
		return 1
	}

	if !declaration.Params[0].IsPointer {
		api.Errorf("in %s, parameter %s is a pointer", syscallName, paramName)
		return 1
	}

	return 0
}

func main() {}
