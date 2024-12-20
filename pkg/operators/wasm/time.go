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
	"time"

	"github.com/tetratelabs/wazero"
	wapi "github.com/tetratelabs/wazero/api"
)

func (i *wasmOperatorInstance) addTimeFuncs(env wazero.HostModuleBuilder) {
	exportFunction(env, "timeNow", i.timeNow,
		[]wapi.ValueType{},
		[]wapi.ValueType{wapi.ValueTypeI64}, // time.Now()
	)
}

// timeNow() returns time.Now()
// Return value:
// - time.Now()
func (i *wasmOperatorInstance) timeNow(ctx context.Context, m wapi.Module, stack []uint64) {
	stack[0] = uint64(time.Now().UnixNano())
}
