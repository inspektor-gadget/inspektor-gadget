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
)

//go:wasmimport env arrayNew
func arrayNew() uint32

//go:wasmimport env arrayLen
func arrayLen(a uint32) int64

//go:wasmimport env arrayGet
func arrayGet(a uint32, i uint32) uint32

//go:wasmimport env arrayAppend
func arrayAppend(a uint32, h uint32) uint32

type Array uint32

func NewArray() Array {
	return Array(arrayNew())
}

func (a Array) Length() (int64, error) {
	ret := arrayLen(uint32(a))
	if ret == -1 {
		return 0, errors.New("getting array length")
	}

	return ret, nil
}

func (a Array) Get(i uint32) (uint32, error) {
	ret := arrayGet(uint32(a), i)
	if ret == 0 {
		return 0, fmt.Errorf("getting array element %d", i)
	}

	return ret, nil
}

func (a Array) Append(h uint32) error {
	ret := arrayAppend(uint32(a), h)
	if ret == 1 {
		return fmt.Errorf("adding handle %d to array element", h)
	}

	return nil
}
