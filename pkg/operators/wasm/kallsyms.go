// Copyright 2025 The Inspektor Gadget authors
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

	"github.com/inspektor-gadget/inspektor-gadget/pkg/kallsyms"
)

func (i *wasmOperatorInstance) addKallsymsFuncs(env wazero.HostModuleBuilder) {
	exportFunction(env, "kallsymsSymbolExists", i.kallsymsSymbolExists,
		[]wapi.ValueType{
			wapi.ValueTypeI64, // Symbol name
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Bool
	)
}

// kallsymsSymbolExists checks if a symbol exists in kallsyms.
// Params:
// - stack[0] is the symbol name
// Return value:
// - 1 if the symbol exists, 0 otherwise
func (i *wasmOperatorInstance) kallsymsSymbolExists(ctx context.Context, m wapi.Module, stack []uint64) {
	symbolNamePtr := stack[0]

	symbolName, err := stringFromStack(m, symbolNamePtr)
	if err != nil {
		i.logger.Warnf("kallsymsSymbolExists: reading string from stack: %v", err)
		stack[0] = 0
		return
	}

	ret := uint32(0)
	if kallsyms.SymbolExists(symbolName) {
		ret = 1
	}

	stack[0] = wapi.EncodeU32(ret)
}
