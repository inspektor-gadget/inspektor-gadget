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

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

func (i *wasmOperatorInstance) addConfigFuncs(env wazero.HostModuleBuilder) {
	exportFunction(env, "setConfig", i.setConfig,
		[]wapi.ValueType{
			wapi.ValueTypeI64, // Key
			wapi.ValueTypeI64, // Value
			wapi.ValueTypeI32, // Kind
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Error
	)
}

// setConfig sets the gadget configuration.
// Params:
// - stack[0] key
// - stack[1] value
// - stack[2] type
// Return value:
// - 0 on success, 1 on error
func (i *wasmOperatorInstance) setConfig(ctx context.Context, m wapi.Module, stack []uint64) {
	if i.config == nil {
		i.logger.Warnf("setConfig: config not initialized")
		stack[0] = 1
		return
	}

	keyPtr := stack[0]
	valuePtr := stack[1]
	typ := api.Kind(wapi.DecodeU32(stack[2]))

	key, err := stringFromStack(m, keyPtr)
	if err != nil {
		i.logger.Warnf("setConfig: reading string from stack: %v", err)
		stack[0] = 1
		return
	}

	switch typ {
	case api.Kind_String:
		val, err := stringFromStack(m, valuePtr)
		if err != nil {
			i.logger.Warnf("setConfig: reading string from stack: %v", err)
			stack[0] = 1
			return
		}
		i.config.Set(key, val)
	default:
		i.logger.Warnf("setConfig: unsupported type: %d", typ)
		stack[0] = 1
		return
	}

	stack[0] = wapi.EncodeU32(0)
}
