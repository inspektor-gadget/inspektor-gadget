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

package uprobetracer

import (
	"bytes"
	"errors"
	"unsafe"
)

// plainDataStruct constrains types to fixed-size structs containing only
// numeric fields (int32, uint32, uint64, fixed-size arrays of int8, etc.).
// These types have no pointers, strings, slices, or interfaces, making them
// safe to reinterpret directly from a byte buffer without serialization.
// Adding a new type here requires verifying it meets these criteria.
type plainDataStruct interface {
	ldCache1 | ldCache1Entry | ldCache2 | ldCache2Entry
}

// reinterpretBytes interprets rawData as a value of type T using direct memory
// reinterpretation (equivalent to a C memcpy/cast). This assumes:
//   - T satisfies plainDataStruct (only fixed-size numeric fields)
//   - rawData is in native byte order (matching the host architecture)
//   - len(rawData) == unsafe.Sizeof(T)
//
// This is used instead of encoding/binary.Read for performance: binary.Read
// uses reflection and allocates intermediate buffers, which is significantly
// slower when called in tight loops (e.g., parsing ~700K ld.so.cache entries).
func reinterpretBytes[T plainDataStruct](obj *T, rawData []byte) error {
	if int(unsafe.Sizeof(*obj)) != len(rawData) {
		return errors.New("reading from bytes: length mismatched")
	}
	*obj = *(*T)(unsafe.Pointer(&rawData[0]))
	return nil
}

// readStringFromBytes reads a null-terminated string starting at startPos in
// data. Returns "" if startPos is out of bounds or no null terminator is found.
// Uses bytes.IndexByte for O(n) performance.
func readStringFromBytes(data []byte, startPos uint32) string {
	if startPos >= uint32(len(data)) {
		return ""
	}
	end := bytes.IndexByte(data[startPos:], 0)
	if end == -1 {
		return ""
	}
	return string(data[startPos : startPos+uint32(end)])
}

// matchStringInBytes checks whether the null-terminated string at startPos in
// data begins with prefix. This avoids allocating a Go string for entries that
// don't match, reducing GC pressure when scanning large caches.
// Note: string([]byte) in a comparison is optimized by the Go compiler to
// avoid allocation when the result is not stored.
func matchStringInBytes(data []byte, startPos uint32, prefix string) bool {
	if startPos >= uint32(len(data)) {
		return false
	}
	remaining := data[startPos:]
	if uint32(len(remaining)) < uint32(len(prefix)) {
		return false
	}
	return string(remaining[:len(prefix)]) == prefix
}
