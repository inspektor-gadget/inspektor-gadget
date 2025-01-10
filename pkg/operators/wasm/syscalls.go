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
	"bytes"
	"context"
	"encoding/binary"
	"sync"

	"github.com/tetratelabs/wazero"
	wapi "github.com/tetratelabs/wazero/api"

	syscallhelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/traceloop/syscall-helpers"
)

func (i *wasmOperatorInstance) addSyscallsDeclarationsFuncs(env wazero.HostModuleBuilder) {
	exportFunction(env, "getSyscallName", i.getSyscallName,
		[]wapi.ValueType{wapi.ValueTypeI32}, // Syscall ID
		[]wapi.ValueType{wapi.ValueTypeI64}, // Syscall Name
	)

	exportFunction(env, "getSyscallDeclaration", i.getSyscallDeclaration,
		[]wapi.ValueType{
			wapi.ValueTypeI64, // Syscall Name
			wapi.ValueTypeI64, // Syscall Declaration pointer
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // SyscallDeclaration or Error
	)
}

// getSyscallName returns the syscall name corresponding to the given ID.
// Params:
// - stack[0]
// Return value:
// - Syscall name on success, 0 on error
func (i *wasmOperatorInstance) getSyscallName(ctx context.Context, m wapi.Module, stack []uint64) {
	syscallID := uint16(stack[0])
	syscallName := syscallhelpers.SyscallGetName(syscallID)

	bufPtr, err := i.writeToGuestMemory(ctx, []byte(syscallName))
	if err != nil {
		i.logger.Warnf("getSyscallName: allocating guest memory for %s: %v", syscallName, err)
		stack[0] = 0
		return
	}

	stack[0] = bufPtr
}

// Keep in sync with wasmapi/go/syscall.go.
const (
	isPointerFlag = 1 << iota
)

// Keep in sync with wasmapi/go/syscall.go.
type syscallParam struct {
	name  [32]byte
	flags uint32
}

// Keep in sync with wasmapi/go/syscall.go.
type syscallDeclaration struct {
	// landlock_create_ruleset() is one of the longest syscall name with 24
	// characters, let's round up to 32 to be sure.
	name     [32]byte
	nrParams uint8
	_        [3]byte
	// syscalls have maximum 6 arguments:
	// https://github.com/torvalds/linux/blob/7cb1b4663150/include/linux/syscalls.h#L231
	params [6]syscallParam
}

// getSyscallDeclaration gets a syscall declaration.
// Params:
// - stack[0] is the name of the syscall (string encoded)
// - stack[1] is a pointer to a syscallDeclaration structure used to store the result.
// Return value:
// - 0 on success, 1 on error
func (i *wasmOperatorInstance) getSyscallDeclaration(ctx context.Context, m wapi.Module, stack []uint64) {
	syscallNamePtr := stack[0]
	syscallDeclPtr := stack[1]

	syscallName, err := stringFromStack(m, syscallNamePtr)
	if err != nil {
		i.logger.Warnf("getSyscallDeclaration: reading string from stack: %v", err)
		stack[0] = 1
		return
	}

	// This map can be big, so let's do it only once and if needed.
	i.syscallsDeclarations, err = sync.OnceValues(func() (map[string]syscallhelpers.SyscallDeclaration, error) {
		return syscallhelpers.GatherSyscallsDeclarations()
	})()
	if err != nil {
		i.logger.Warnf("getSyscallDeclaration: gathering syscall declarations: %v", err)
		stack[0] = 1
		return
	}

	declaration, err := syscallhelpers.GetSyscallDeclaration(i.syscallsDeclarations, syscallName)
	if err != nil {
		i.logger.Warnf("getSyscallDeclaration: getting syscall declaration for %q: %v", syscallName, err)
		stack[0] = 1
		return
	}

	syscallDecl := syscallDeclaration{nrParams: declaration.GetParameterCount()}
	copy(syscallDecl.name[:], syscallName)

	for idx := range syscallDecl.nrParams {
		name, err := declaration.GetParameterName(idx)
		if err != nil {
			i.logger.Warnf("getSyscallDeclaration: getting parameter name %d for %q: %v", idx, syscallName, err)
			stack[0] = 1
			return
		}

		isPointer, err := declaration.ParamIsPointer(idx)
		if err != nil {
			i.logger.Warnf("getSyscallDeclaration: getting parameter type %d for %q: %v", syscallName, err)
			stack[0] = 1
			return
		}

		copy(syscallDecl.params[idx].name[:], name)
		if isPointer {
			syscallDecl.params[idx].flags |= isPointerFlag
		}
	}

	var buf bytes.Buffer
	// WASM is little endian:
	// https://webassembly.org/docs/portability/
	err = binary.Write(&buf, binary.LittleEndian, syscallDecl)
	if err != nil {
		i.logger.Warnf("getSyscallDeclaration: converting syscall declaration to bytes: %v", err)
		stack[0] = 1
		return
	}

	err = bufToStack(m, buf.Bytes(), syscallDeclPtr)
	if err != nil {
		i.logger.Warnf("getSyscallDeclaration: writing back syscall declaration to stack: %v", err)
		stack[0] = 1
		return
	}

	stack[0] = 0
}
