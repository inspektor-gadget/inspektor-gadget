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

package api

import (
	"errors"
	"fmt"
	"runtime"
	_ "unsafe"
)

//go:wasmimport ig newDataSource
//go:linkname newDataSource newDataSource
func newDataSource(name uint64, typ uint32) uint32

//go:wasmimport ig getDataSource
//go:linkname getDataSource getDataSource
func getDataSource(name uint64) uint32

//go:wasmimport ig dataSourceSubscribe
//go:linkname dataSourceSubscribe dataSourceSubscribe
func dataSourceSubscribe(ds uint32, typ uint32, prio uint32, cb uint64) uint32

//go:wasmimport ig dataSourceGetField
//go:linkname dataSourceGetField dataSourceGetField
func dataSourceGetField(ds uint32, name uint64) uint32

//go:wasmimport ig dataSourceAddField
//go:linkname dataSourceAddField dataSourceAddField
func dataSourceAddField(ds uint32, name uint64, kind uint32) uint32

//go:wasmimport ig dataSourceNewPacketSingle
//go:linkname dataSourceNewPacketSingle dataSourceNewPacketSingle
func dataSourceNewPacketSingle(ds uint32) uint32

//go:wasmimport ig dataSourceNewPacketArray
//go:linkname dataSourceNewPacketArray dataSourceNewPacketArray
func dataSourceNewPacketArray(ds uint32) uint32

//go:wasmimport ig dataSourceEmitAndRelease
//go:linkname dataSourceEmitAndRelease dataSourceEmitAndRelease
func dataSourceEmitAndRelease(ds uint32, packet uint32) uint32

//go:wasmimport ig dataSourceRelease
//go:linkname dataSourceRelease dataSourceRelease
func dataSourceRelease(ds uint32, packet uint32) uint32

//go:wasmimport ig dataSourceUnreference
//go:linkname dataSourceUnreference dataSourceUnreference
func dataSourceUnreference(ds uint32) uint32

//go:wasmimport ig dataSourceIsReferenced
//go:linkname dataSourceIsReferenced dataSourceIsReferenced
func dataSourceIsReferenced(ds uint32) uint32

//go:wasmimport ig dataArrayNew
//go:linkname dataArrayNew dataArrayNew
func dataArrayNew(d uint32) uint32

//go:wasmimport ig dataArrayAppend
//go:linkname dataArrayAppend dataArrayAppend
func dataArrayAppend(d uint32, data uint32) uint32

//go:wasmimport ig dataArrayRelease
//go:linkname dataArrayRelease dataArrayRelease
func dataArrayRelease(d uint32, data uint32) uint32

//go:wasmimport ig dataArrayLen
//go:linkname dataArrayLen dataArrayLen
func dataArrayLen(d uint32) uint32

//go:wasmimport ig dataArrayGet
//go:linkname dataArrayGet dataArrayGet
func dataArrayGet(d uint32, index uint32) uint32

type (
	DataFunc   func(DataSource, Data)
	ArrayFunc  func(DataSource, DataArray) error
	PacketFunc func(DataSource, Packet) error
)

type subscriptionType uint32

const (
	subcriptionTypeInvalid subscriptionType = 0
	subscriptionTypeData   subscriptionType = 1
	subscriptionTypeArray  subscriptionType = 2
	subscriptionTypePacket subscriptionType = 3
)

// go linkname doesn't work with constants. Define some variables to be able to
// use it on pkg/operators/wasm/consts_test.go
var (
	subscriptionTypeDataVar   uint32 = uint32(subscriptionTypeData)
	subscriptionTypeArrayVar  uint32 = uint32(subscriptionTypeArray)
	subscriptionTypePacketVar uint32 = uint32(subscriptionTypePacket)
	_                                = subscriptionTypeDataVar
	_                                = subscriptionTypeArrayVar
	_                                = subscriptionTypePacketVar
)

type DataSourceType uint32

const (
	DataSourceTypeUndefined DataSourceType = 0
	DataSourceTypeSingle    DataSourceType = 1
	DataSourceTypeArray     DataSourceType = 2
)

var (
	dsSubscriptionCtr = uint64(0)
	dsSubcriptions    = map[uint64]any{}
)

const (
	// Well known data sources
	DataSourceContainers = "containers"

	// Data source "containers" has a field EventType with the following possible values:
	// - PRECREATE
	// - CREATED
	// - DELETED
	// The maximum length is 9. Keeping more for future compatibility.
	DataSourceContainersEventTypeMaxSize = 16
)

//go:wasmexport dataSourceCallback
func dataSourceCallback(cbID uint64, ds uint32, data uint32) {
	cb, ok := dsSubcriptions[cbID]
	if !ok {
		return
	}

	switch cb := cb.(type) {
	case DataFunc:
		cb(DataSource(ds), Data(data))
	case ArrayFunc:
		cb(DataSource(ds), DataArray(data))
	case PacketFunc:
		cb(DataSource(ds), Packet(data))
	}
}

type (
	Packet       uint32
	DataSource   uint32
	Field        uint32
	Data         uint32
	DataArray    uint32
	PacketSingle uint32
	PacketArray  uint32
)

func GetDataSource(name string) (DataSource, error) {
	ret := getDataSource(uint64(stringToBufPtr(name)))
	runtime.KeepAlive(name)
	if ret == 0 {
		return 0, fmt.Errorf("datasource %s not found", name)
	}
	return DataSource(ret), nil
}

func NewDataSource(name string, typ DataSourceType) (DataSource, error) {
	ret := newDataSource(uint64(stringToBufPtr(name)), uint32(typ))
	runtime.KeepAlive(name)
	if ret == 0 {
		return 0, fmt.Errorf("creating datasource %q", name)
	}
	return DataSource(ret), nil
}

func (ds DataSource) subscribe(cb any, priority uint32, typ subscriptionType) error {
	dsSubscriptionCtr++
	dsSubcriptions[dsSubscriptionCtr] = cb
	ret := dataSourceSubscribe(uint32(ds), uint32(typ), priority, dsSubscriptionCtr)
	if ret != 0 {
		return fmt.Errorf("subscribing to datasource")
	}
	return nil
}

func (ds DataSource) Subscribe(cb DataFunc, priority uint32) error {
	return ds.subscribe(cb, priority, subscriptionTypeData)
}

func (ds DataSource) SubscribeArray(cb ArrayFunc, priority uint32) error {
	return ds.subscribe(cb, priority, subscriptionTypeArray)
}

func (ds DataSource) SubscribePacket(cb PacketFunc, priority uint32) error {
	return ds.subscribe(cb, priority, subscriptionTypePacket)
}

func (ds DataSource) NewPacketSingle() (PacketSingle, error) {
	ret := dataSourceNewPacketSingle(uint32(ds))
	if ret == 0 {
		return 0, errors.New("creating packet")
	}
	return PacketSingle(ret), nil
}

func (ds DataSource) NewPacketArray() (PacketArray, error) {
	ret := dataSourceNewPacketArray(uint32(ds))
	if ret == 0 {
		return 0, errors.New("creating packet")
	}
	return PacketArray(ret), nil
}

func (ds DataSource) EmitAndRelease(packet Packet) error {
	ret := dataSourceEmitAndRelease(uint32(ds), uint32(packet))
	if ret != 0 {
		return fmt.Errorf("emitting data")
	}
	return nil
}

func (ds DataSource) Release(packet Packet) error {
	ret := dataSourceRelease(uint32(ds), uint32(packet))
	if ret != 0 {
		return fmt.Errorf("releasing data")
	}
	return nil
}

func (ds DataSource) Unreference() error {
	ret := dataSourceUnreference(uint32(ds))
	if ret != 0 {
		return fmt.Errorf("unreferencing data source")
	}
	return nil
}

func (ds DataSource) IsReferenced() bool {
	return dataSourceIsReferenced(uint32(ds)) == 1
}

func (ds DataSource) GetField(name string) (Field, error) {
	ret := dataSourceGetField(uint32(ds), uint64(stringToBufPtr(name)))
	runtime.KeepAlive(name)
	if ret == 0 {
		return 0, fmt.Errorf("field %q not found", name)
	}
	return Field(ret), nil
}

func (ds DataSource) AddField(name string, kind FieldKind) (Field, error) {
	ret := dataSourceAddField(uint32(ds), uint64(stringToBufPtr(name)), uint32(kind))
	runtime.KeepAlive(name)
	if ret == 0 {
		return 0, fmt.Errorf("adding field %q", name)
	}
	return Field(ret), nil
}

func (d DataArray) New() Data {
	ret := dataArrayNew(uint32(d))
	return Data(ret)
}

func (d DataArray) Append(data Data) error {
	ret := dataArrayAppend(uint32(d), uint32(data))
	if ret != 0 {
		return fmt.Errorf("appending data")
	}
	return nil
}

func (d DataArray) Release(data Data) error {
	ret := dataArrayRelease(uint32(d), uint32(data))
	if ret != 0 {
		return fmt.Errorf("releasing data")
	}
	return nil
}

func (d DataArray) Len() int {
	return int(dataArrayLen(uint32(d)))
}

func (d DataArray) Get(index int) Data {
	ret := dataArrayGet(uint32(d), uint32(index))
	return Data(ret)
}

type FieldKind uint32

// Keep in sync with pkg/gadget-service/api/api.proto
const (
	Kind_Invalid FieldKind = 0
	Kind_Bool    FieldKind = 1
	Kind_Int8    FieldKind = 2
	Kind_Int16   FieldKind = 3
	Kind_Int32   FieldKind = 4
	Kind_Int64   FieldKind = 5
	Kind_Uint8   FieldKind = 6
	Kind_Uint16  FieldKind = 7
	Kind_Uint32  FieldKind = 8
	Kind_Uint64  FieldKind = 9
	Kind_Float32 FieldKind = 10
	Kind_Float64 FieldKind = 11
	Kind_String  FieldKind = 12
	Kind_CString FieldKind = 13
	Kind_Bytes   FieldKind = 14
)
