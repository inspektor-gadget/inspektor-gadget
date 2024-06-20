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
	"errors"

	"github.com/tetratelabs/wazero"
	wapi "github.com/tetratelabs/wazero/api"
)

func bufFromStack(m wapi.Module, val uint64) ([]byte, error) {
	slen := uint32(val >> 32)
	soffs := uint32(val & 0xFFFFFFFF)
	buf, ok := m.Memory().Read(soffs, slen)
	if !ok {
		return nil, errors.New("invalid pointer")
	}
	return buf, nil
}

func stringFromStack(m wapi.Module, val uint64) (string, error) {
	buf, err := bufFromStack(m, val)
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

func exportFunction(
	env wazero.HostModuleBuilder,
	name string,
	fn func(ctx context.Context, m wapi.Module, stack []uint64),
	params, results []wapi.ValueType,
) {
	env.NewFunctionBuilder().
		WithGoModuleFunction(wapi.GoModuleFunc(fn), params, results).
		Export(name)
}
