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
	"unsafe"
)

//go:wasmimport env fieldGetScalar
//go:linkname fieldGetScalar fieldGetScalar
func fieldGetScalar(field uint32, data uint32, kind uint32, errPtr uint32) uint64

//go:wasmimport env fieldGetBuffer
//go:linkname fieldGetBuffer fieldGetBuffer
func fieldGetBuffer(field uint32, data uint32, kind uint32, dst uint64) int32

//go:wasmimport env fieldSet
//go:linkname fieldSet fieldSet
func fieldSet(field uint32, data uint32, kind uint32, value uint64) uint32

//go:wasmimport env fieldAddTag
//go:linkname fieldAddTag fieldAddTag
func fieldAddTag(field uint32, tag uint64) uint32

var (
	errSetField = errors.New("error setting field")
	errGetField = errors.New("error getting field")
)

func (f Field) getScalar(data Data, kind FieldKind) (uint64, error) {
	var err uint32
	errPtr := uintptr(unsafe.Pointer(&err))
	val := fieldGetScalar(uint32(f), uint32(data), uint32(kind), uint32(errPtr))
	if err != 0 {
		return 0, errGetField
	}
	return val, nil
}

func (f Field) set(data Data, kind FieldKind, value uint64) error {
	ret := fieldSet(uint32(f), uint32(data), uint32(kind), value)
	if ret != 0 {
		return errSetField
	}
	return nil
}

func (f Field) Int8(data Data) (int8, error) {
	val, err := f.getScalar(data, Kind_Int8)
	return int8(val), err
}

func (f Field) SetInt8(data Data, value int8) error {
	return f.set(data, Kind_Int8, uint64(value))
}

func (f Field) Int16(data Data) (int16, error) {
	val, err := f.getScalar(data, Kind_Int16)
	return int16(val), err
}

func (f Field) SetInt16(data Data, value int16) error {
	return f.set(data, Kind_Int16, uint64(value))
}

func (f Field) Int32(data Data) (int32, error) {
	val, err := f.getScalar(data, Kind_Int32)
	return int32(val), err
}

func (f Field) SetInt32(data Data, value int32) error {
	return f.set(data, Kind_Int32, uint64(value))
}

func (f Field) Int64(data Data) (int64, error) {
	val, err := f.getScalar(data, Kind_Int64)
	return int64(val), err
}

func (f Field) SetInt64(data Data, value int64) error {
	return f.set(data, Kind_Int64, uint64(value))
}

func (f Field) Uint8(data Data) (uint8, error) {
	val, err := f.getScalar(data, Kind_Uint8)
	return uint8(val), err
}

func (f Field) SetUint8(data Data, value uint8) error {
	return f.set(data, Kind_Uint8, uint64(value))
}

func (f Field) Uint16(data Data) (uint16, error) {
	val, err := f.getScalar(data, Kind_Uint16)
	return uint16(val), err
}

func (f Field) SetUint16(data Data, value uint16) error {
	return f.set(data, Kind_Uint16, uint64(value))
}

func (f Field) Uint32(data Data) (uint32, error) {
	val, err := f.getScalar(data, Kind_Uint32)
	return uint32(val), err
}

func (f Field) SetUint32(data Data, value uint32) error {
	return f.set(data, Kind_Uint32, uint64(value))
}

func (f Field) Uint64(data Data) (uint64, error) {
	val, err := f.getScalar(data, Kind_Uint64)
	return uint64(val), err
}

func (f Field) SetUint64(data Data, value uint64) error {
	return f.set(data, Kind_Uint64, uint64(value))
}

func (f Field) Float32(data Data) (float32, error) {
	val, err := f.getScalar(data, Kind_Float32)
	return math.Float32frombits(uint32(val)), err
}

func (f Field) SetFloat32(data Data, value float32) error {
	return f.set(data, Kind_Float32, uint64(math.Float32bits(value)))
}

func (f Field) Float64(data Data) (float64, error) {
	val, err := f.getScalar(data, Kind_Float64)
	return math.Float64frombits(uint64(val)), err
}

func (f Field) SetFloat64(data Data, value float64) error {
	return f.set(data, Kind_Float64, uint64(math.Float64bits(value)))
}

func (f Field) String(data Data, maxSize uint32) (string, error) {
	dst := make([]byte, maxSize)
	n, err := f.Bytes(data, dst)
	if err != nil {
		return "", err
	}
	return fromCString(dst[:n]), nil
}

func (f Field) SetString(data Data, str string) error {
	err := f.set(data, Kind_String, uint64(stringToBufPtr(str)))
	runtime.KeepAlive(str)
	return err
}

// Bytes get the bytes of a field of type string or []byte into an
// existing slice. It returns the number of bytes copied.
func (f Field) Bytes(data Data, dst []byte) (uint32, error) {
	ret := fieldGetBuffer(uint32(f), uint32(data), uint32(Kind_Bytes), uint64(bytesToBufPtr(dst)))
	if ret == -1 {
		return 0, errors.New("error getting bytes")
	}
	return uint32(ret), nil
}

func (f Field) SetBytes(data Data, buf []byte) error {
	err := f.set(data, Kind_Bytes, uint64(bytesToBufPtr(buf)))
	runtime.KeepAlive(buf)
	return err
}

func (f Field) Bool(data Data) (bool, error) {
	val, err := f.getScalar(data, Kind_Bool)
	return val == 1, err
}

func (f Field) SetBool(data Data, b bool) error {
	var value uint64
	if b {
		value = 1
	}
	return f.set(data, Kind_Bool, uint64(value))
}

func (f Field) AddTag(tag string) error {
	ret := fieldAddTag(uint32(f), uint64(stringToBufPtr(tag)))
	runtime.KeepAlive(tag)
	if ret != 0 {
		return errors.New("error adding tag")
	}
	return nil
}
