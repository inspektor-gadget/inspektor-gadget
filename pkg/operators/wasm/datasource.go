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
	"fmt"

	"github.com/tetratelabs/wazero"
	wapi "github.com/tetratelabs/wazero/api"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

func (i *wasmOperatorInstance) addDataSourceFuncs(env wazero.HostModuleBuilder) {
	exportFunction(env, "newDataSource", i.newDataSource,
		[]wapi.ValueType{
			wapi.ValueTypeI64, // DataSourceName
			wapi.ValueTypeI32, // DataSourceType
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // DataSource
	)

	exportFunction(env, "getDataSource", i.getDataSource,
		[]wapi.ValueType{wapi.ValueTypeI64}, // DataSourceName
		[]wapi.ValueType{wapi.ValueTypeI32}, // DataSource
	)

	exportFunction(env, "dataSourceSubscribe", i.dataSourceSubscribe,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // DataSource
			wapi.ValueTypeI32, // Type (0: Data, 1: Array, 2: Packet)
			wapi.ValueTypeI32, // Priority
			wapi.ValueTypeI64, // CallbackID
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Error
	)

	exportFunction(env, "dataSourceGetField", i.dataSourceGetField,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // DataSource
			wapi.ValueTypeI64, // FieldName
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Accessor
	)

	exportFunction(env, "dataSourceAddField", i.dataSourceAddField,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // DataSource
			wapi.ValueTypeI64, // FieldName
			wapi.ValueTypeI32, // FieldKind
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Accessor
	)

	exportFunction(env, "dataSourceNewPacketSingle", i.dataSourceNewPacketSingle,
		[]wapi.ValueType{wapi.ValueTypeI32}, // DataSource
		[]wapi.ValueType{wapi.ValueTypeI32}, // Packet
	)

	exportFunction(env, "dataSourceNewPacketArray", i.dataSourceNewPacketArray,
		[]wapi.ValueType{wapi.ValueTypeI32}, // DataSource
		[]wapi.ValueType{wapi.ValueTypeI32}, // Packet
	)

	exportFunction(env, "dataSourceEmitAndRelease", i.dataSourceEmitAndRelease,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // DataSource
			wapi.ValueTypeI32, // Packet
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Error
	)

	exportFunction(env, "dataSourceRelease", i.dataSourceRelease,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // DataSource
			wapi.ValueTypeI32, // Packet
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Error
	)

	exportFunction(env, "dataArrayNew", i.dataArrayNew,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // DataArray
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Data,
	)

	exportFunction(env, "dataArrayAppend", i.dataArrayAppend,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // DataArray
			wapi.ValueTypeI32, // Data
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Error
	)

	exportFunction(env, "dataArrayRelease", i.dataArrayRelease,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // DataArray
			wapi.ValueTypeI32, // Data
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Error
	)

	exportFunction(env, "dataArrayLen", i.dataArrayLen,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // DataArray
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Len
	)

	exportFunction(env, "dataArrayGet", i.dataArrayGet,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // DataArray
			wapi.ValueTypeI32, // Index
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Data,
	)
}

// newDataSource creates a new datasource.
// Params:
// - stack[0] is the name of the datasource (string encoded)
// - stack[1] is the type of the datasource
// Return value:
// - DataSource handle on success, 0 on error
func (i *wasmOperatorInstance) newDataSource(ctx context.Context, m wapi.Module, stack []uint64) {
	dsNamePtr := stack[0]
	dsType := wapi.DecodeU32(stack[1])

	dsName, err := stringFromStack(m, dsNamePtr)
	if err != nil {
		i.logger.Warnf("newDataSource: reading string from stack: %v", err)
		stack[0] = 0
		return
	}

	ds, err := i.gadgetCtx.RegisterDataSource(datasource.Type(dsType), dsName)
	if err != nil {
		i.logger.Warnf("failed to register datasource: %v", err)
		stack[0] = 0
		return
	}
	stack[0] = wapi.EncodeU32(i.addHandle(ds))
}

// getDataSource returns a data source by its name.
// Params:
// - stack[0] is the name of the datasource (string encoded)
// Return value:
// - DataSource handle on success, 0 on error
func (i *wasmOperatorInstance) getDataSource(ctx context.Context, m wapi.Module, stack []uint64) {
	dsNamePtr := stack[0]

	dsName, err := stringFromStack(m, dsNamePtr)
	if err != nil {
		i.logger.Warnf("getDataSource: reading string from stack: %v", err)
		stack[0] = 0
		return
	}
	ds := i.gadgetCtx.GetDataSources()[dsName]
	if ds == nil {
		i.logger.Warnf("datasource not found %q", dsName)
		stack[0] = 0
		return
	}
	stack[0] = wapi.EncodeU32(i.addHandle(ds))
}

// dataSourceGetField returns a handle to a data source.
// Params:
// - stack[0]: DataSource handle
// - stack[1]: Field name
// Return value:
// - Field handle on success, 0 on error
func (i *wasmOperatorInstance) dataSourceGetField(ctx context.Context, m wapi.Module, stack []uint64) {
	dsHandle := wapi.DecodeU32(stack[0])
	fieldNamePtr := stack[1]

	ds, ok := getHandle[datasource.DataSource](i, dsHandle)
	if !ok {
		stack[0] = 0
		return
	}
	fieldName, err := stringFromStack(m, fieldNamePtr)
	if err != nil {
		i.logger.Warnf("dataSourceGetField: reading string from stack: %v", err)
		stack[0] = 0
		return
	}
	acc := ds.GetField(fieldName)
	stack[0] = wapi.EncodeU32(i.addHandle(acc))
}

// dataSourceAddField add a field to the data source and returns its handle.
// Params:
// - stack[0]: DataSource handle
// - stack[1]: Field name
// - stack[2]: Field kind
// Return value:
// - Field handle on success, 0 on error
func (i *wasmOperatorInstance) dataSourceAddField(ctx context.Context, m wapi.Module, stack []uint64) {
	dsHandle := wapi.DecodeU32(stack[0])
	fieldNamePtr := stack[1]
	fieldKind := wapi.DecodeU32(stack[2])
	// TODO: add kind max?
	if fieldKind > uint32(api.Kind_Bytes) {
		i.logger.Warnf("dataSourceAddField: invalid field kind %d", fieldKind)
		stack[0] = 0
		return
	}

	ds, ok := getHandle[datasource.DataSource](i, dsHandle)
	if !ok {
		stack[0] = 0
		return
	}
	fieldName, err := stringFromStack(m, fieldNamePtr)
	if err != nil {
		i.logger.Warnf("dataSourceAddField: reading string from stack: %v", err)
		stack[0] = 0
		return
	}
	acc, err := ds.AddField(fieldName, api.Kind(fieldKind))
	if err != nil {
		i.logger.Warnf("adding field %q to datasource %q: %v", fieldName, ds.Name(), err)
		stack[0] = 0
		return
	}
	stack[0] = wapi.EncodeU32(i.addHandle(acc))
}

type subscriptionType uint32

const (
	subcriptionTypeInvalid subscriptionType = 0
	subscriptionTypeData   subscriptionType = 1
	subscriptionTypeArray  subscriptionType = 2
	subscriptionTypePacket subscriptionType = 3
)

// dataSourceSubscribe subscribes to the datasource.
// Params:
// - stack[0]: DataSource handle
// - stack[1]: Type (0: Data, 1: Array, 2: Packet)
// - stack[2]: Priority
// - stack[3]: Callback ID
// Return value:
// - 0 on success, 1 on error
func (i *wasmOperatorInstance) dataSourceSubscribe(ctx context.Context, m wapi.Module, stack []uint64) {
	dsHandle := wapi.DecodeU32(stack[0])
	typ := wapi.DecodeU32(stack[1])
	prio := wapi.DecodeI32(stack[2])
	cbID := stack[3]

	if i.dataSourceCallback == nil {
		i.logger.Warnf("wasm module doesn't export dataSourceCallback")
		stack[0] = 1
		return
	}

	ds, ok := getHandle[datasource.DataSource](i, dsHandle)
	if !ok {
		stack[0] = 1
		return
	}
	var err error

	switch subscriptionType(typ) {
	case subscriptionTypeData:
		err = ds.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
			tmpData := i.addHandle(data)
			_, err := i.dataSourceCallback.Call(ctx, cbID, stack[0], wapi.EncodeU32(tmpData))
			i.delHandle(tmpData)
			return err
		}, int(prio))
	case subscriptionTypeArray:
		err = ds.SubscribeArray(func(source datasource.DataSource, data datasource.DataArray) error {
			tmpData := i.addHandle(data)
			_, err := i.dataSourceCallback.Call(ctx, cbID, stack[0], wapi.EncodeU32(tmpData))
			i.delHandle(tmpData)
			return err
		}, int(prio))
	case subscriptionTypePacket:
		err = ds.SubscribePacket(func(source datasource.DataSource, data datasource.Packet) error {
			tmpData := i.addHandle(data)
			_, err := i.dataSourceCallback.Call(ctx, cbID, stack[0], wapi.EncodeU32(tmpData))
			i.delHandle(tmpData)
			return err
		}, int(prio))
	default:
		err = fmt.Errorf("unknown subscription type %d", typ)
	}

	if err != nil {
		i.logger.Warnf("failed to subscribe to datasource: %v", err)
		stack[0] = 1
		return
	}

	stack[0] = 0
}

// dataSourceNewPacketSingle allocates and returns a handle to a new data instance.
// Params:
// - stack[0]: DataSource handle
// Return value:
// - Packet handle on success, 0 on error
func (i *wasmOperatorInstance) dataSourceNewPacketSingle(ctx context.Context, m wapi.Module, stack []uint64) {
	dsHandle := wapi.DecodeU32(stack[0])

	ds, ok := getHandle[datasource.DataSource](i, dsHandle)
	if !ok {
		stack[0] = 0
		return
	}
	packet, err := ds.NewPacketSingle()
	if err != nil {
		i.logger.Warnf("failed to create NewPacketSingle: %v", err)
		stack[0] = 0
		return
	}
	stack[0] = wapi.EncodeU32(i.addHandle(packet))
}

// dataSourceNewPacketArray allocates and returns a handle to a new data instance.
// Params:
// - stack[0]: DataSource handle
// Return value:
// - Packet handle on success, 0 on error
func (i *wasmOperatorInstance) dataSourceNewPacketArray(ctx context.Context, m wapi.Module, stack []uint64) {
	dsHandle := wapi.DecodeU32(stack[0])

	ds, ok := getHandle[datasource.DataSource](i, dsHandle)
	if !ok {
		stack[0] = 0
		return

	}
	packet, err := ds.NewPacketArray()
	if err != nil {
		i.logger.Warnf("failed to call NewPacketArray: %v", err)
		stack[0] = 0
		return
	}
	stack[0] = wapi.EncodeU32(i.addHandle(packet))
}

// dataSourceEmitAndRelease emits and releases the data.
// Params:
// - stack[0]: DataSource handle
// - stack[1]: Packet handle
// Return value:
// - 0 on success, 1 on error
func (i *wasmOperatorInstance) dataSourceEmitAndRelease(ctx context.Context, m wapi.Module, stack []uint64) {
	dsHandle := wapi.DecodeU32(stack[0])
	packetHandle := wapi.DecodeU32(stack[1])

	ds, ok := getHandle[datasource.DataSource](i, dsHandle)
	if !ok {
		stack[0] = 1
		return
	}
	packet, ok := getHandle[datasource.Packet](i, packetHandle)
	if !ok {
		i.logger.Warnf("packet handle %d not found", packetHandle)
		stack[0] = 1
		return
	}
	if err := ds.EmitAndRelease(packet); err != nil {
		i.logger.Warnf("failed to emit and release packet: %v", err)
		stack[0] = 1
		return
	}
	stack[0] = 0
}

// dataSourceRelease releases the data.
// Params:
// - stack[0]: DataSource handle
// - stack[1]: Packet handle
// Return value:
// - 0 on success, 1 on error
func (i *wasmOperatorInstance) dataSourceRelease(ctx context.Context, m wapi.Module, stack []uint64) {
	dsHandle := wapi.DecodeU32(stack[0])
	packetHandle := wapi.DecodeU32(stack[1])

	ds, ok := getHandle[datasource.DataSource](i, dsHandle)
	if !ok {
		stack[0] = 1
		return
	}
	packet, ok := getHandle[datasource.Packet](i, packetHandle)
	if !ok {
		stack[0] = 1
		return
	}
	ds.Release(packet)
	stack[0] = 0
}

// dataArrayNew allocates and returns a new element on the array
// Params:
// - stack[0]: DataArray handle
// Return value:
// - Data handle on success, 0 on error
func (i *wasmOperatorInstance) dataArrayNew(ctx context.Context, m wapi.Module, stack []uint64) {
	dataArrayHandle := wapi.DecodeU32(stack[0])

	dataArray, ok := getHandle[datasource.DataArray](i, dataArrayHandle)
	if !ok {
		stack[0] = 0
		return
	}

	data := dataArray.New()
	stack[0] = wapi.EncodeU32(i.addHandle(data))
}

// dataArrayAppend appends Data to the array
// Params:
// - stack[0]: DataArray handle
// - stack[1]: Data handle
// Return value:
// - 0 on success, 1 on error
func (i *wasmOperatorInstance) dataArrayAppend(ctx context.Context, m wapi.Module, stack []uint64) {
	dataArrayHandle := wapi.DecodeU32(stack[0])
	dataHandle := wapi.DecodeU32(stack[1])

	dataArray, ok := getHandle[datasource.DataArray](i, dataArrayHandle)
	if !ok {
		stack[0] = 1
		return
	}

	data, ok := getHandle[datasource.Data](i, dataHandle)
	if !ok {
		i.logger.Warnf("Data handle %d not found", stack[0])
		stack[0] = 1
		return
	}

	dataArray.Append(data)
	stack[0] = 0
}

// dataArrayRelease releases the memory of Data; Data may not be used after calling this
// Params:
// - stack[0]: DataArray handle
// - stack[1]: Data handle
// Return value:
// - 0 on success, 1 on error
func (i *wasmOperatorInstance) dataArrayRelease(ctx context.Context, m wapi.Module, stack []uint64) {
	dataArrayHandle := wapi.DecodeU32(stack[0])
	dataHandle := wapi.DecodeU32(stack[1])

	dataArray, ok := getHandle[datasource.DataArray](i, dataArrayHandle)
	if !ok {
		stack[0] = 1
		return
	}

	data, ok := getHandle[datasource.Data](i, dataHandle)
	if !ok {
		stack[0] = 1
		return
	}

	dataArray.Release(data)
	stack[0] = 0
}

// dataArrayLen returns the number of elements in the array
// Params:
// - stack[0]: DataArray handle
// Return value:
// - Number of elements in the array
func (i *wasmOperatorInstance) dataArrayLen(ctx context.Context, m wapi.Module, stack []uint64) {
	dataArrayHandle := wapi.DecodeU32(stack[0])

	dataArray, ok := getHandle[datasource.DataArray](i, dataArrayHandle)
	if !ok {
		stack[0] = 0
		return
	}

	stack[0] = wapi.EncodeI32(int32(dataArray.Len()))
}

// dataArrayGet returns the element at the given index
// Params:
// - stack[0]: DataArray handle
// - stack[1]: Data index
// Return value:
// - Data handle on success, 0 on error
func (i *wasmOperatorInstance) dataArrayGet(ctx context.Context, m wapi.Module, stack []uint64) {
	dataArrayHandle := wapi.DecodeU32(stack[0])

	dataArray, ok := getHandle[datasource.DataArray](i, dataArrayHandle)
	if !ok {
		stack[0] = 0
		return
	}

	data := dataArray.Get(int(wapi.DecodeI32(stack[1])))
	stack[0] = wapi.EncodeU32(i.addHandle(data))
}
