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

// TODO Investigate more this solution as it avoids doing plenty of copy.
// So far, it does not work because we get wrong data while reading buf in dlv.
func anytoBufPtr2[T any](a *T) bufPtr {
	size := reflect.TypeOf(*a).Size()
	if size == 0 {
		return 0
	}

	unsafePtr := unsafe.Pointer(a)
	Infof("unsafePtr: %v", unsafePtr)
	Infof("value: %v", *a)
	return bufPtr(uint64(size)<<32 | uint64(uintptr(unsafePtr)))
}

func readBufPtr(ptr bufPtr) []byte {
	length := ptr >> 32
	buf := make([]byte, length)

	// My kingdom for a memcpy()...
	copy(buf, unsafe.Slice((*byte)(unsafe.Pointer(uintptr(uint32(ptr)))), length))

	return buf
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
