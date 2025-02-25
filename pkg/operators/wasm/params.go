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
)

func (i *wasmOperatorInstance) addParamsFuncs(env wazero.HostModuleBuilder) {
	exportFunction(env, "getParamValue", i.getParamValue,
		[]wapi.ValueType{
			wapi.ValueTypeI64, // ParamKey
			wapi.ValueTypeI64, // Buffer to save param value
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Error
	)
}

// getParamValue returns the value of a param.
// Params:
// - stack[0] parameter key
// - stack[1] buffer where the param value will be written
// Return value:
// - 0 on success, 1 on error
func (i *wasmOperatorInstance) getParamValue(ctx context.Context, m wapi.Module, stack []uint64) {
	paramKeyPtr := stack[0]
	dst := stack[1]

	paramKey, err := stringFromStack(m, paramKeyPtr)
	if err != nil {
		i.logger.Warnf("getParamValue: reading string from stack: %v", err)
		stack[0] = 1
		return
	}

	val, ok := i.paramValues[paramKey]
	if !ok {
		i.logger.Warnf("getParamValue: param %q not found", paramKey)
		stack[0] = 1
		return
	}

	if err = i.writeToDstBuffer([]byte(val), dst); err != nil {
		i.logger.Warnf("getParamValue: writing to guest memory: %v", err)
		stack[0] = 1
		return
	}

	stack[0] = 0
}
