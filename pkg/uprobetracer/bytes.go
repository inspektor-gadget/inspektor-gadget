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
	"encoding/binary"
	"errors"
	"unsafe"
)

func readFromBytes[T any](obj *T, rawData []byte) error {
	if int(unsafe.Sizeof(*obj)) != len(rawData) {
		return errors.New("reading from bytes: length mismatched")
	}
	buffer := bytes.NewBuffer(rawData)
	err := binary.Read(buffer, binary.NativeEndian, obj)
	if err != nil {
		return err
	}
	return nil
}

func readStringFromBytes(data []byte, startPos uint32) string {
	res := ""
	for i := startPos; i < uint32(len(data)); i++ {
		if data[i] == 0 {
			return res
		}
		res += string(data[i])
	}
	return ""
}
