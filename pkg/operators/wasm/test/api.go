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

package main

import (
	"unsafe"
)

type String uint64

func toString(s string) String {
	// TODO: this might be insecure as we don't know whether the GC will not collect
	// the buffer after returning
	buffer := []byte(s)
	bufferPtr := &buffer[0]
	unsafePtr := uintptr(unsafe.Pointer(bufferPtr))
	return String(uint64(len(buffer))<<32 | uint64(unsafePtr))
}

func (s String) String() string {
	if s == 0 {
		return ""
	}
	sb := make([]byte, s>>32)
	copy(sb, unsafe.Slice((*byte)(unsafe.Pointer(uintptr(s&0xFFFFFFFF))), s>>32))
	return string(sb)
}

func (s String) Free() {
	mfree(uint32(s & 0xFFFFFFFF))
}

//export xlog
func xlog(s String)

//export getDataSource
func getDataSource(name String) DataSource

//export newDataSource
func newDataSource(name String) DataSource

//export getField
func getField(ds DataSource) Field

//export mfree
func mfree(uint32)

//export freeHost
func freeHost(entry uint32)

//export dataSourceSubscribe
func dataSourceSubscribe(ds DataSource, prio uint32, cb uint64)

//export dataSourceNewData
func dataSourceNewData(ds DataSource) Data

//export dataSourceEmitAndRelease
func dataSourceEmitAndRelease(ds DataSource, data Data)

//export dataSourceGetField
func dataSourceGetField(ds DataSource, name String) Field

//export dataSourceAddField
func dataSourceAddField(ds DataSource, name String) Field

//export fieldAccessorGetString
func fieldAccessorGetString(acc Field, data Data) String

//export fieldAccessorSetString
func fieldAccessorSetString(acc Field, data Data, str String)

var (
	dsSubscriptionCtr = uint64(0)
	dsSubcriptions    = map[uint64]func(DataSource, Data){}
)

//export dsCallback
func dsCallback(cbID uint64, ds uint32, data uint32) {
	cb, ok := dsSubcriptions[cbID]
	if !ok {
		return
	}
	cb(DataSource(ds), Data(data))
}

type (
	DataSource uint32
	Field      uint32
	Data       uint32
)

func GetDataSource(name string) DataSource {
	return getDataSource(toString(name))
}

func NewDataSource(name string) DataSource {
	return newDataSource(toString(name))
}

func (ds DataSource) Subscribe(cb func(DataSource, Data), priority uint32) {
	dsSubscriptionCtr++
	dsSubcriptions[dsSubscriptionCtr] = cb
	dataSourceSubscribe(ds, priority, dsSubscriptionCtr)
}

func (ds DataSource) NewData() Data {
	return dataSourceNewData(ds)
}

func (ds DataSource) EmitAndRelease(data Data) {
	dataSourceEmitAndRelease(ds, data)
}

func (ds DataSource) GetField(name string) Field {
	return dataSourceGetField(ds, toString(name))
}

func (ds DataSource) AddField(name string) Field {
	return dataSourceAddField(ds, toString(name))
}

func (f Field) String(data Data) (res string) {
	str := fieldAccessorGetString(f, data)
	res = str.String()
	str.Free()
	return
}

func (f Field) SetString(data Data, str string) {
	fieldAccessorSetString(f, data, toString(str))
}

func Log(message string) {
	xlog(toString(message))
}
