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

// TODO: is it possible to make it work without cgo?

// #include <stdlib.h>
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"unsafe"
)

// bufPtr encodes the pointer and length of a buffer as a uint64
// The pointer is stored in the lower 32 bits and the length in the upper 32 bits
type bufPtr uint64

func (b bufPtr) free() {
	if b == 0 {
		return
	}
	C.free(unsafe.Pointer(uintptr(b & 0xFFFFFFFF)))
}

// stringToBufPtr returns a bufPtr that encodes the pointer and length of the
// input string. Callers must guarantee that the passed string is kept alive
// until the buffer is used. This can be done by using runtime.KeepAlive().
func stringToBufPtr(s string) bufPtr {
	// The return value of unsafe.StringData() for an empty string is undefined,
	// hence handle this case here.
	if len(s) == 0 {
		return 0
	}
	unsafePtr := unsafe.Pointer(unsafe.StringData(s))
	return bufPtr(uint64(len(s))<<32 | uint64(uintptr(unsafePtr)))
}

// anytoBufPtr returns a bufPtr that encodes the pointer and length of the
// input.
// The input is first encoded to binary buffer, which is then used as the
// returned bufPtr.
// WARNING the binary encoding will only works on with fixed size data, *i.e.*
// with int32 but not with int, as this data would be exchanged from 32 bits
// WASM VM to host which can be 64 bits.
func anytoBufPtr(a any) (bufPtr, error) {
	buf := make([]byte, reflect.TypeOf(a).Size())
	buffer := new(bytes.Buffer)

	// TODO Use binary.Encode() once compiler no more yells about it:
	// undefined: binary.Encode
	err := binary.Write(buffer, binary.NativeEndian, a)
	if err != nil {
		return bufPtr(0), fmt.Errorf("converting %T to []byte: %w", a, err)
	}

	// TODO Remove this when using binary.Encode().
	copy(buf, buffer.Bytes())

	return bytesToBufPtr(buf), nil
}

// Taken from:
// https://github.com/golang/go/blob/38f85967873b1cd48c20681c5dff0e9f3de18516/src/runtime/runtime2.go#L178-L181
// We do not care about itab, so we just use a pointer to the data at correct
// offset in this struct.
type iface struct {
	itab *any
	data unsafe.Pointer
}

func anytoBufPtr2(a any) (bufPtr, error) {
	typ := reflect.TypeOf(a)
	size := typ.Size()
	if size == 0 {
		return 0, nil
	}

	var unsafePtr unsafe.Pointer
	switch typ.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr, reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128:
		// Let's say we call map.Update(struct{ 42, 43, 'c'}, 42)
		// The key argument would be passed by address, but the second by value.
		// So, in this case iface.data would be the address for the key but the
		// actual value for the value, i.e. 42.
		// Then, we need to take a pointer over the data instead of the data
		// directly.
		unsafePtr = unsafe.Pointer(&((*iface)(unsafe.Pointer(&a))).data)
	default:
		unsafePtr = ((*iface)(unsafe.Pointer(&a))).data
	}

	return bufPtr(uint64(size)<<32 | uint64(uintptr(unsafePtr))), nil
}

// bytesToBufPtr returns a bufPtr that encodes the pointer and length of the
// input buffer. Callers must use runtime.KeepAlive on the input buffer to
// ensure it is not garbage collected.
func bytesToBufPtr(b []byte) bufPtr {
	unsafePtr := unsafe.Pointer(unsafe.SliceData(b))
	return bufPtr(uint64(len(b))<<32 | uint64(uintptr(unsafePtr)))
}

// string returns a copy of the string stored in the buffer.
// The called must call free() on the buffer when done.
func (b bufPtr) string() string {
	if b == 0 {
		return ""
	}
	// create a string that users the pointer as storage
	orig := unsafe.String((*byte)(unsafe.Pointer(uintptr(b&0xFFFFFFFF))), int(b>>32))
	// clone it
	return strings.Clone(orig)
}

// bytes returns a copy of the bytes stored in the buffer.
// The called must call free() on the buffer when done.
func (b bufPtr) bytes() []byte {
	if b == 0 {
		return nil
	}
	// create a slice that uses the pointer as storage
	orig := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(b&0xFFFFFFFF))), int(b>>32))
	// clone it
	return slices.Clone(orig)
}
