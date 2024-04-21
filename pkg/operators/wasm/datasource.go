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

	wapi "github.com/tetratelabs/wazero/api"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
)

func (i *wasmOperatorInstance) newDataSource(ctx context.Context, m wapi.Module, stack []uint64) {
	dsName, err := stringFromStack(m, stack, 0)
	if err != nil {
		stack[0] = 0
		return
	}
	ds, err := i.gadgetCtx.RegisterDataSource(0, dsName)
	if err != nil {
		stack[0] = 0
		return
	}
	stack[0] = wapi.EncodeU32(i.addToMemMap(ds))
}

func (i *wasmOperatorInstance) getDataSource(ctx context.Context, m wapi.Module, stack []uint64) {
	dsName, err := stringFromStack(m, stack, 0)
	if err != nil {
		stack[0] = 0
		return
	}
	i.gadgetCtx.Logger().Debugf("wasm getting datasource %q", dsName)
	ds := i.gadgetCtx.GetDataSources()[dsName]
	if ds == nil {
		stack[0] = 0
		return
	}
	stack[0] = wapi.EncodeU32(i.addToMemMap(ds))
}

func (i *wasmOperatorInstance) dataSourceGetField(ctx context.Context, m wapi.Module, stack []uint64) {
	ds, ok := i.getFromMemMap(wapi.DecodeU32(stack[0])).(datasource.DataSource)
	if !ok {
		stack[0] = 0
		i.gadgetCtx.Logger().Warnf("datasource not present")
		return
	}
	fieldName, err := stringFromStack(m, stack, 1)
	if err != nil {
		stack[0] = 0
		i.gadgetCtx.Logger().Warnf("string invalid")
		return
	}
	i.gadgetCtx.Logger().Warnf("getting field %q", fieldName)
	acc := ds.GetField(fieldName)
	stack[0] = wapi.EncodeU32(i.addToMemMap(acc))
}

func (i *wasmOperatorInstance) dataSourceAddField(ctx context.Context, m wapi.Module, stack []uint64) {
	ds, ok := i.getFromMemMap(wapi.DecodeU32(stack[0])).(datasource.DataSource)
	if !ok {
		stack[0] = 0
		i.gadgetCtx.Logger().Warnf("datasource not present")
		return
	}
	fieldName, err := stringFromStack(m, stack, 1)
	if err != nil {
		stack[0] = 0
		i.gadgetCtx.Logger().Warnf("string invalid")
		return
	}
	i.gadgetCtx.Logger().Warnf("adding field %q", fieldName)
	acc, err := ds.AddField(fieldName)
	if err != nil {
		stack[0] = 0
		return
	}
	stack[0] = wapi.EncodeU32(i.addToMemMap(acc))
}

func (i *wasmOperatorInstance) dataSourceSubscribe(ctx context.Context, m wapi.Module, stack []uint64) {
	ds, ok := i.getFromMemMap(wapi.DecodeU32(stack[0])).(datasource.DataSource)
	if !ok {
		stack[0] = 0
		return
	}
	prio := wapi.DecodeI32(stack[1])
	cbID := stack[2]
	cb := m.ExportedFunction("dsCallback")
	ds.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
		tmpDS := i.addToMemMap(source)
		tmpData := i.addToMemMap(data)
		_, err := cb.Call(ctx, cbID, wapi.EncodeU32(tmpDS), wapi.EncodeU32(tmpData))
		i.freeFromMemMap(tmpDS)
		i.freeFromMemMap(tmpData)
		return err
	}, int(prio))
}

func (i *wasmOperatorInstance) dataSourceNewData(ctx context.Context, m wapi.Module, stack []uint64) {
	ds, ok := i.getFromMemMap(wapi.DecodeU32(stack[0])).(datasource.DataSource)
	if !ok {
		stack[0] = 0
		i.gadgetCtx.Logger().Warnf("datasource not present")
		return
	}
	data := ds.NewData()
	stack[0] = wapi.EncodeU32(i.addToMemMap(data))
}

func (i *wasmOperatorInstance) dataSourceEmitAndRelease(ctx context.Context, m wapi.Module, stack []uint64) {
	ds, ok := i.getFromMemMap(wapi.DecodeU32(stack[0])).(datasource.DataSource)
	if !ok {
		i.gadgetCtx.Logger().Warnf("datasource not present")
		return
	}
	data, ok := i.getFromMemMap(wapi.DecodeU32(stack[1])).(datasource.Data)
	if !ok {
		i.gadgetCtx.Logger().Warnf("data not present")
		return
	}
	ds.EmitAndRelease(data)
}
