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
		[]wapi.ValueType{wapi.ValueTypeI64}, // Syscall Name
		[]wapi.ValueType{wapi.ValueTypeI32}, // SyscallDeclaration
	)

	exportFunction(env, "syscallDeclarationGetParameterCount", i.syscallDeclarationGetParameterCount,
		[]wapi.ValueType{wapi.ValueTypeI32}, // SyscallDeclaration
		[]wapi.ValueType{wapi.ValueTypeI32}, // Parameters count
	)

	exportFunction(env, "syscallDeclarationParamIsPointer", i.syscallDeclarationParamIsPointer,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // SyscallDeclaration
			wapi.ValueTypeI32, // Parameter count
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Bool
	)

	exportFunction(env, "syscallDeclarationGetParameterName", i.syscallDeclarationGetParameterName,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // SyscallDeclaration
			wapi.ValueTypeI32, // Parameter count
		},
		[]wapi.ValueType{wapi.ValueTypeI64}, // Parameter name
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

// getSyscallDeclaration gets a syscall declaration.
// Params:
// - stack[0] is the name of the syscall (string encoded)
// Return value:
// - Syscall declaration handle on success, 0 on error
func (i *wasmOperatorInstance) getSyscallDeclaration(ctx context.Context, m wapi.Module, stack []uint64) {
	syscallNamePtr := stack[0]

	syscallName, err := stringFromStack(m, syscallNamePtr)
	if err != nil {
		i.logger.Warnf("getSyscallDeclaration: reading string from stack: %v", err)
		stack[0] = 0
		return
	}

	if i.syscallsDeclarations == nil {
		// This map can be big, so let's do it only once and if needed.
		declarations, err := syscallhelpers.GatherSyscallsDeclarations()
		if err != nil {
			i.logger.Warnf("getSyscallDeclaration: gathering syscall declarations: %v", err)
			stack[0] = 0
			return
		}
		i.syscallsDeclarations = declarations
	}

	declaration, err := syscallhelpers.GetSyscallDeclaration(i.syscallsDeclarations, syscallName)
	if err != nil {
		i.logger.Warnf("getSyscallDeclaration: getting syscall declaration for %q: %v", syscallName, err)
		stack[0] = 0
		return
	}

	stack[0] = wapi.EncodeU32(i.addHandle(&declaration))
}

// syscallDeclarationGetParameterCount returns the number of parameter for the given syscall declaration.
// Params:
// - stack[0]: Syscall declaration handle
// Return value:
// - Number of parameter on success, -1 on error.
func (i *wasmOperatorInstance) syscallDeclarationGetParameterCount(ctx context.Context, m wapi.Module, stack []uint64) {
	syscallDeclarationHandle := wapi.DecodeU32(stack[0])

	syscallDeclaration, ok := getHandle[*syscallhelpers.SyscallDeclaration](i, syscallDeclarationHandle)
	if !ok {
		stack[0] = wapi.EncodeI32(-1)
		return
	}

	stack[0] = wapi.EncodeI32(int32(syscallDeclaration.GetParameterCount()))
}

// syscallDeclarationParamIsPointer returns the number of parameter for the given syscall declaration.
// Params:
// - stack[0]: Syscall declaration handle
// - stack[1]: Parameter number
// Return value:
// - 1 if true, 2 if false or 0 on error
func (i *wasmOperatorInstance) syscallDeclarationParamIsPointer(ctx context.Context, m wapi.Module, stack []uint64) {
	syscallDeclarationHandle := wapi.DecodeU32(stack[0])
	paramNumber := wapi.DecodeU32(stack[1])

	syscallDeclaration, ok := getHandle[*syscallhelpers.SyscallDeclaration](i, syscallDeclarationHandle)
	if !ok {
		stack[0] = 0
		return
	}

	isParamPointer, err := syscallDeclaration.ParamIsPointer(uint8(paramNumber))
	if err != nil {
		i.logger.Warnf("syscallDeclarationParamIsPointer: checking whether parameter %d is a pointer: %v", paramNumber, err)
		stack[0] = 0
		return
	}

	if isParamPointer {
		stack[0] = 1
	} else {
		stack[0] = 2
	}
}

// syscallDeclarationGetParameterName returns parameter name for the given parameter and syscall declaration.
// Params:
// - stack[0]: Syscall declaration handle
// - stack[1]: Parameter number
// Return value:
// - TODO, 0 on error
func (i *wasmOperatorInstance) syscallDeclarationGetParameterName(ctx context.Context, m wapi.Module, stack []uint64) {
	syscallDeclarationHandle := wapi.DecodeU32(stack[0])
	paramNumber := wapi.DecodeU32(stack[1])

	syscallDeclaration, ok := getHandle[*syscallhelpers.SyscallDeclaration](i, syscallDeclarationHandle)
	if !ok {
		stack[0] = 0
		return
	}

	paramName, err := syscallDeclaration.GetParameterName(uint8(paramNumber))
	if err != nil {
		i.logger.Warnf("syscallDeclarationGetParameterName: getting parameter %d name: %v", paramNumber, err)
		stack[0] = 0
		return
	}

	bufPtr, err := i.writeToGuestMemory(ctx, []byte(paramName))
	if err != nil {
		i.logger.Warnf("syscallDeclarationGetParameterName: allocating guest memory for %s: %v", paramName, err)
		stack[0] = 0
		return
	}
	stack[0] = bufPtr
}
