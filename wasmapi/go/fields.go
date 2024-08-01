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
	"math"
	"runtime"
)

//go:wasmimport env fieldGet
func fieldGet(field uint32, data uint32, kind uint32) uint64

//go:wasmimport env fieldSet
func fieldSet(field uint32, data uint32, kind uint32, value uint64) uint32

var errSetField = errors.New("error setting field")

func (f Field) Int8(data Data) (int8, error) {
	val := fieldGet(uint32(f), uint32(data), uint32(Kind_Int8))
	return int8(val), nil
}

func (f Field) SetInt8(data Data, value int8) error {
	ret := fieldSet(uint32(f), uint32(data), uint32(Kind_Int8), uint64(value))
	if ret != 0 {
		return errSetField
	}
	return nil
}

func (f Field) Int16(data Data) (int16, error) {
	val := fieldGet(uint32(f), uint32(data), uint32(Kind_Int16))
	return int16(val), nil
}

func (f Field) SetInt16(data Data, value int16) error {
	ret := fieldSet(uint32(f), uint32(data), uint32(Kind_Int16), uint64(value))
	if ret != 0 {
		return errSetField
	}
	return nil
}

func (f Field) Int32(data Data) (int32, error) {
	val := fieldGet(uint32(f), uint32(data), uint32(Kind_Int32))
	return int32(val), nil
}

func (f Field) SetInt32(data Data, value int32) error {
	ret := fieldSet(uint32(f), uint32(data), uint32(Kind_Int32), uint64(value))
	if ret != 0 {
		return errSetField
	}
	return nil
}

func (f Field) Int64(data Data) (int64, error) {
	val := fieldGet(uint32(f), uint32(data), uint32(Kind_Int64))
	return int64(val), nil
}

func (f Field) SetInt64(data Data, value int64) error {
	ret := fieldSet(uint32(f), uint32(data), uint32(Kind_Int64), uint64(value))
	if ret != 0 {
		return errSetField
	}
	return nil
}

func (f Field) Uint8(data Data) (uint8, error) {
	val := fieldGet(uint32(f), uint32(data), uint32(Kind_Uint8))
	return uint8(val), nil
}

func (f Field) SetUint8(data Data, value uint8) error {
	ret := fieldSet(uint32(f), uint32(data), uint32(Kind_Uint8), uint64(value))
	if ret != 0 {
		return errSetField
	}
	return nil
}

func (f Field) Uint16(data Data) (uint16, error) {
	val := fieldGet(uint32(f), uint32(data), uint32(Kind_Uint16))
	return uint16(val), nil
}

func (f Field) SetUint16(data Data, value uint16) error {
	ret := fieldSet(uint32(f), uint32(data), uint32(Kind_Uint16), uint64(value))
	if ret != 0 {
		return errSetField
	}
	return nil
}

func (f Field) Uint32(data Data) (uint32, error) {
	val := fieldGet(uint32(f), uint32(data), uint32(Kind_Uint32))
	return uint32(val), nil
}

func (f Field) SetUint32(data Data, value uint32) error {
	ret := fieldSet(uint32(f), uint32(data), uint32(Kind_Uint32), uint64(value))
	if ret != 0 {
		return errSetField
	}
	return nil
}

func (f Field) Uint64(data Data) (uint64, error) {
	val := fieldGet(uint32(f), uint32(data), uint32(Kind_Uint64))
	return uint64(val), nil
}

func (f Field) SetUint64(data Data, value uint64) error {
	ret := fieldSet(uint32(f), uint32(data), uint32(Kind_Uint64), uint64(value))
	if ret != 0 {
		return errSetField
	}
	return nil
}

func (f Field) Float32(data Data) (float32, error) {
	val := fieldGet(uint32(f), uint32(data), uint32(Kind_Float32))
	return math.Float32frombits(uint32(val)), nil
}

func (f Field) SetFloat32(data Data, value float32) error {
	ret := fieldSet(uint32(f), uint32(data), uint32(Kind_Float32), uint64(math.Float32bits(value)))
	if ret != 0 {
		return errSetField
	}
	return nil
}

func (f Field) Float64(data Data) (float64, error) {
	val := fieldGet(uint32(f), uint32(data), uint32(Kind_Float64))
	return math.Float64frombits(uint64(val)), nil
}

func (f Field) SetFloat64(data Data, value float64) error {
	ret := fieldSet(uint32(f), uint32(data), uint32(Kind_Float64), uint64(math.Float64bits(value)))
	if ret != 0 {
		return errSetField
	}
	return nil
}

func (f Field) String(data Data) (string, error) {
	str := bufPtr(fieldGet(uint32(f), uint32(data), uint32(Kind_String)))
	ret := str.string()
	str.free()
	return ret, nil
}

func (f Field) SetString(data Data, str string) error {
	ret := fieldSet(uint32(f), uint32(data), uint32(Kind_String), uint64(stringToBufPtr(str)))
	runtime.KeepAlive(str)
	if ret != 0 {
		return errSetField
	}
	return nil
}

func (f Field) Bytes(data Data) ([]byte, error) {
	buf := bufPtr(fieldGet(uint32(f), uint32(data), uint32(Kind_Bytes)))
	ret := buf.bytes()
	buf.free()
	return ret, nil
}

func (f Field) SetBytes(data Data, buf []byte) error {
	ret := fieldSet(uint32(f), uint32(data), uint32(Kind_Bytes), uint64(bytesToBufPtr(buf)))
	runtime.KeepAlive(buf)
	if ret != 0 {
		return errSetField
	}
	return nil
}

func (f Field) Bool(data Data) (bool, error) {
	val := fieldGet(uint32(f), uint32(data), uint32(Kind_Bool))
	return val == 1, nil
}

func (f Field) SetBool(data Data, b bool) error {
	var value uint64
	if b {
		value = 1
	}
	ret := fieldSet(uint32(f), uint32(data), uint32(Kind_Bool), value)
	if ret != 0 {
		return errSetField
	}
	return nil
}
