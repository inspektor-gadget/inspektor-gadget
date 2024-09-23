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

// This program tries as hard as it can to break the host by calling functions
// with wrong arguments. It uses the low level functions directly as the goal is
// to test the host and not the wrapper API. Tests under dataarray and fields
// test also the higher level API.
package main

import (
	"fmt"
	"runtime/debug"
	"unsafe"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

// We need to copy some declarations from the API to have access to the low
// level details.

type subscriptionType uint32

const (
	subcriptionTypeInvalid subscriptionType = 0
	subscriptionTypeData   subscriptionType = 1
	subscriptionTypeArray  subscriptionType = 2
	subscriptionTypePacket subscriptionType = 3
)

//go:wasmimport env gadgetLog
func gadgetLog(level uint32, str uint64)

//go:wasmimport env newDataSource
func newDataSource(name uint64, typ uint32) uint32

//go:wasmimport env getDataSource
func getDataSource(name uint64) uint32

//go:wasmimport env dataSourceSubscribe
func dataSourceSubscribe(ds uint32, typ uint32, prio uint32, cb uint64) uint32

//go:wasmimport env dataSourceGetField
func dataSourceGetField(ds uint32, name uint64) uint32

//go:wasmimport env dataSourceAddField
func dataSourceAddField(ds uint32, name uint64, kind uint32) uint32

//go:wasmimport env dataSourceNewPacketSingle
func dataSourceNewPacketSingle(ds uint32) uint32

//go:wasmimport env dataSourceNewPacketArray
func dataSourceNewPacketArray(ds uint32) uint32

//go:wasmimport env dataSourceEmitAndRelease
func dataSourceEmitAndRelease(ds uint32, packet uint32) uint32

//go:wasmimport env dataSourceRelease
func dataSourceRelease(ds uint32, packet uint32) uint32

//go:wasmimport env dataArrayNew
func dataArrayNew(d uint32) uint32

//go:wasmimport env dataArrayAppend
func dataArrayAppend(d uint32, data uint32) uint32

//go:wasmimport env dataArrayRelease
func dataArrayRelease(d uint32, data uint32) uint32

//go:wasmimport env dataArrayLen
func dataArrayLen(d uint32) uint32

//go:wasmimport env dataArrayGet
func dataArrayGet(d uint32, index uint32) uint32

//go:wasmimport env fieldGet
func fieldGet(acc uint32, data uint32, kind uint32) uint64

//go:wasmimport env fieldSet
func fieldSet(acc uint32, data uint32, kind uint32, value uint64) uint32

//go:wasmimport env getParamValue
func getParamValue(key uint64) uint64

//go:wasmimport env setConfig
func setConfig(key uint64, val uint64, kind uint32) uint32

func stringToBufPtr(s string) uint64 {
	unsafePtr := unsafe.Pointer(unsafe.StringData(s))
	return uint64(len(s))<<32 | uint64(uintptr(unsafePtr))
}

func logAndPanic(msg string) {
	gadgetLog(uint32(api.ErrorLevel), stringToBufPtr(msg))
	panic(msg)
}

func assertZero[T uint64 | uint32](v T, msg string) {
	if v != 0 {
		logAndPanic(fmt.Sprintf("%d is not zero: %s", v, msg))
	}
}

func assertNonZero[T uint64 | uint32](v T, msg string) {
	if v == 0 {
		logAndPanic(fmt.Sprintf("v is zero: %s", msg))
	}
}

func assertEqual[T uint64 | uint32](v1, v2 T, msg string) {
	if v1 != v2 {
		logAndPanic(fmt.Sprintf("%d != %d: %s", v1, v2, msg))
	}
}

//export gadgetInit
func gadgetInit() int {
	// Disable GC to avoid it cleaning up the memory we're using
	debug.SetGCPercent(-1)

	const (
		dsSingleName = "myarrayds"
		dsArrayName  = "myarrayds"
		fieldName    = "myfield"
		// Invalid string: Too big (4GB) and offset too big (64MB)
		invalidStrPtr = uint64(1024 * 1024 << 32)
	)

	// Create some resources for testing at the very beginning
	dsSingleHandle := newDataSource(stringToBufPtr(dsSingleName), uint32(api.DataSourceTypeSingle))
	assertNonZero(dsSingleHandle, "newDataSource: creating new single")

	dsArrayHandle := newDataSource(stringToBufPtr(dsArrayName), uint32(api.DataSourceTypeArray))
	assertNonZero(dsArrayHandle, "newDataSource: creating new array")

	fieldHandle := dataSourceAddField(dsSingleHandle, stringToBufPtr(fieldName), uint32(api.Kind_Uint32))
	assertNonZero(fieldHandle, "dataSourceAddField: creating new")

	/********** Log **********/
	gadgetLog(uint32(api.ErrorLevel), invalidStrPtr)
	gadgetLog(42, stringToBufPtr("hello-world"))          // invalid log level
	gadgetLog(uint32(api.ErrorLevel), stringToBufPtr("")) // empty string

	/********** DataSource **********/
	// TODO: it doesn't fail. However it's not related to wasm but the gadget context
	//assertZero(newDataSource(stringToBufPtr(dsName)), "newDataSource: duplicated")
	assertZero(newDataSource(invalidStrPtr, uint32(api.DataSourceTypeSingle)), "newDataSource: invalid name ptr")
	assertZero(newDataSource(stringToBufPtr("foo"), 42), "newDataSource: invalid type")

	assertNonZero(getDataSource(stringToBufPtr(dsSingleName)), "getDataSource: existing")
	assertZero(getDataSource(stringToBufPtr("foo")), "getDataSource: non existing")
	assertZero(getDataSource(invalidStrPtr), "getDataSource: invalid name ptr")

	assertZero(dataSourceSubscribe(dsSingleHandle, uint32(subscriptionTypeData), 0, 0), "dataSourceSubscribe: single")
	assertZero(dataSourceSubscribe(dsSingleHandle, uint32(subscriptionTypePacket), 0, 0), "dataSourceSubscribe: single + packet")
	assertZero(dataSourceSubscribe(dsArrayHandle, uint32(subscriptionTypeArray), 0, 0), "dataSourceSubscribe: array")
	assertZero(dataSourceSubscribe(dsArrayHandle, uint32(subscriptionTypePacket), 0, 0), "dataSourceSubscribe: array + packet")
	assertZero(dataSourceSubscribe(dsArrayHandle, uint32(subscriptionTypeData), 0, 0), "dataSourceSubscribe: array + single")
	assertNonZero(dataSourceSubscribe(42, uint32(subscriptionTypeData), 0, 0), "dataSourceSubscribe: bad handle")
	assertNonZero(dataSourceSubscribe(fieldHandle, uint32(subscriptionTypeData), 0, 0), "dataSourceSubscribe: bad handle type")
	assertNonZero(dataSourceSubscribe(dsSingleHandle, uint32(subscriptionTypeArray), 0, 0), "dataSourceSubscribe: bad handle type (single)")
	assertNonZero(dataSourceSubscribe(dsSingleHandle, 1005, 0, 0), "dataSourceSubscribe: bad subscription type")

	assertZero(dataSourceAddField(dsSingleHandle, stringToBufPtr(fieldName), uint32(api.Kind_Uint32)), "dataSourceAddField: duplicated")
	assertZero(dataSourceAddField(42, stringToBufPtr("foo"), uint32(api.Kind_Uint32)), "dataSourceAddField: bad handle")
	assertZero(dataSourceAddField(fieldHandle, stringToBufPtr("foo"), uint32(api.Kind_Uint32)), "dataSourceAddField: bad handle type")
	assertZero(dataSourceAddField(dsSingleHandle, stringToBufPtr("foo"), uint32(1005)), "dataSourceAddField: bad kind")

	assertNonZero(dataSourceGetField(dsSingleHandle, stringToBufPtr(fieldName)), "dataSourceGetField: existing")
	assertZero(dataSourceGetField(42, stringToBufPtr("foo")), "dataSourceGetField: non existing")
	assertZero(dataSourceGetField(dsSingleHandle, invalidStrPtr), "dataSourceGetField: invalid name ptr")

	packetSingleHandle := dataSourceNewPacketSingle(dsSingleHandle)
	assertNonZero(packetSingleHandle, "dataSourceNewPacketSingle: creating new")
	assertZero(dataSourceNewPacketSingle(42), "dataSourceNewPacketSingle: bad handle")
	assertZero(dataSourceNewPacketSingle(fieldHandle), "dataSourceNewPacketSingle: bad handle type")
	assertZero(dataSourceNewPacketSingle(dsArrayHandle), "dataSourceNewPacketSingle: bad datasource type")

	packetArrayHandle := dataSourceNewPacketArray(dsArrayHandle)
	assertNonZero(packetArrayHandle, "dataSourceNewPacketArray: creating new")
	assertZero(dataSourceNewPacketArray(42), "dataSourceNewPacketArray: bad handle")
	assertZero(dataSourceNewPacketArray(fieldHandle), "dataSourceNewPacketArray: bad handle type")
	assertZero(dataSourceNewPacketArray(dsSingleHandle), "dataSourceNewPacketArray: bad datasource type")

	assertNonZero(dataSourceEmitAndRelease(42, packetSingleHandle), "dataSourceEmitAndRelease: bad handle")
	assertNonZero(dataSourceEmitAndRelease(fieldHandle, packetSingleHandle), "dataSourceEmitAndRelease: bad datasource handle type")
	assertNonZero(dataSourceEmitAndRelease(dsSingleHandle, 42), "dataSourceEmitAndRelease: bad packet handle")
	assertNonZero(dataSourceEmitAndRelease(dsSingleHandle, fieldHandle), "dataSourceEmitAndRelease: bad packet handle type ")

	assertZero(dataSourceRelease(dsSingleHandle, packetSingleHandle), "dataSourceRelease: ok")
	assertZero(dataSourceRelease(dsSingleHandle, packetSingleHandle), "dataSourceRelease: double release")
	assertNonZero(dataSourceRelease(42, packetSingleHandle), "dataSourceRelease: bad handle")
	assertNonZero(dataSourceRelease(fieldHandle, packetSingleHandle), "dataSourceRelease: bad handle type")
	assertNonZero(dataSourceRelease(dsSingleHandle, 42), "dataSourceRelease: bad packet handle")
	assertNonZero(dataSourceRelease(dsSingleHandle, fieldHandle), "dataSourceRelease: bad packet handle type")

	dataElemHandle := dataArrayNew(packetArrayHandle)
	assertNonZero(dataElemHandle, "dataArrayNew: creating new")
	assertZero(dataArrayNew(42), "dataArrayNew: bad handle")
	assertZero(dataArrayNew(fieldHandle), "dataArrayNew: bad handle type")

	assertZero(dataArrayAppend(packetArrayHandle, dataElemHandle), "dataArrayAppend: ok")
	assertNonZero(dataArrayAppend(packetArrayHandle, 42), "dataArrayAppend: bad data handle")
	assertNonZero(dataArrayAppend(packetArrayHandle, fieldHandle), "dataArrayAppend: bad data handle type")
	assertNonZero(dataArrayAppend(42, dataElemHandle), "dataArrayAppend: bad handle")
	assertNonZero(dataArrayAppend(fieldHandle, dataElemHandle), "dataArrayAppend: bad array handle type")

	assertEqual(dataArrayLen(packetArrayHandle), 1, "dataArrayLen")
	assertZero(dataArrayLen(42), "dataArrayLen: bad handle")
	assertZero(dataArrayLen(packetSingleHandle), "dataArrayLen: bad handle type")

	assertZero(dataArrayRelease(packetArrayHandle, dataElemHandle), "dataArrayRelease: ok")
	assertZero(dataArrayRelease(packetArrayHandle, dataElemHandle), "dataArrayRelease: double release")
	assertNonZero(dataArrayRelease(packetArrayHandle, 42), "dataArrayRelease: bad data handle")
	assertNonZero(dataArrayRelease(packetArrayHandle, fieldHandle), "dataArrayRelease: bad data handle type")
	assertNonZero(dataArrayRelease(42, dataElemHandle), "dataArrayRelease: bad array handle")
	assertNonZero(dataArrayRelease(fieldHandle, dataElemHandle), "dataArrayRelease: bad array handle type")

	assertNonZero(dataArrayGet(packetArrayHandle, 0), "dataArrayGet: index 0")
	assertZero(dataArrayGet(packetArrayHandle, 1), "dataArrayGet: index 1")
	assertZero(dataArrayGet(42, 0), "dataArrayGet: bad handle")
	assertZero(dataArrayGet(packetSingleHandle, 0), "dataArrayGet: bad handle type")

	/* Fields */
	dataHandle := dataSourceNewPacketSingle(dsSingleHandle)
	assertNonZero(dataHandle, "dataSourceNewPacketSingle: creating new")

	assertNonZero(fieldSet(fieldHandle, dataHandle, uint32(api.Kind_Uint32), 1234), "fieldSet: ok")
	assertNonZero(fieldSet(fieldHandle, dataHandle, uint32(api.Kind_Uint64), 1234), "fieldSet: bad kind")
	assertNonZero(fieldSet(fieldHandle, dataHandle, 1005, 1234), "fieldSet: bad kind")
	assertNonZero(fieldSet(fieldHandle, fieldHandle, uint32(api.Kind_Uint32), 1234), "fieldSet: bad data handle")
	assertNonZero(fieldSet(dataHandle, dataHandle, uint32(api.Kind_Uint32), 1234), "fieldSet: bad field handle")

	assertEqual(uint32(fieldGet(fieldHandle, dataHandle, uint32(api.Kind_Uint32))), 1234, "fieldGet: ok")
	fieldGet(fieldHandle, dataHandle, 1005)
	fieldGet(fieldHandle, fieldHandle, uint32(api.Kind_Uint32))
	fieldGet(dataHandle, dataHandle, uint32(api.Kind_Uint32))

	/* Params */
	assertZero(getParamValue(stringToBufPtr("non-existing-param")), "getParamValue: not-found")
	assertZero(getParamValue(invalidStrPtr), "getParamValue: invalid key ptr")

	/* Config */
	assertZero(setConfig(stringToBufPtr("key"), stringToBufPtr("value"), uint32(api.Kind_String)), "setConfig: ok")
	assertNonZero(setConfig(stringToBufPtr("key"), stringToBufPtr("value"), 1005), "setConfig: bad kind")
	assertNonZero(setConfig(invalidStrPtr, stringToBufPtr("value"), uint32(api.Kind_String)), "setConfig: bad key ptr")
	assertNonZero(setConfig(stringToBufPtr("key"), invalidStrPtr, uint32(api.Kind_String)), "setConfig: bad value ptr")

	return 0
}

func main() {}
