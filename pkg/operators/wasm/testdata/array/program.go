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
	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

//export gadgetInit
func gadgetInit() int {
	array := api.NewArray()

	length, err := array.Length()
	if err != nil {
		api.Errorf("getting array length")
		return 1
	}

	expectedLength := int64(0)
	if length != expectedLength {
		api.Errorf("getting array length: expected %d, got %d", expectedLength, length)
		return 1
	}

	idx := uint32(0)
	if _, err = array.Get(idx); err == nil {
		api.Errorf("getting array element %d: no element", idx)
		return 1
	}

	for i := range 5 {
		err := array.Append(uint32(i))
		if err != nil {
			api.Errorf("adding element %d to array", i)
			return 1
		}
	}

	length, err = array.Length()
	if err != nil {
		api.Errorf("getting array length")
		return 1
	}

	expectedLength = int64(5)
	if length != expectedLength {
		api.Errorf("getting array length: expected %d, got %d", expectedLength, length)
		return 1
	}

	idx = uint32(4)
	elem, err := array.Get(idx)
	if err != nil {
		api.Errorf("getting array element %d: no element", idx)
		return 1
	}

	expectedElem := uint32(4)
	if elem != expectedElem {
		api.Errorf("getting array element %d: expected %d, got %d", idx, expectedElem, elem)
		return 1
	}

	return 0
}

func main() {}
