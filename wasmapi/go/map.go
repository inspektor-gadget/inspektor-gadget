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
	"fmt"
	"reflect"
	"runtime"
)

//go:wasmimport env getMap
func getMap(name uint64) uint32

//go:wasmimport env mapLookup
func mapLookup(m uint32, keyptr uint64, valueptr uint64) uint32

//go:wasmimport env mapUpdate
func mapUpdate(m uint32, keyptr uint64, valueptr uint64, flags uint64) uint32

//go:wasmimport env mapDelete
func mapDelete(m uint32, keyptr uint64) uint32

type Map uint32

type MapUpdateFlags uint64

// Taken from:
// https://github.com/cilium/ebpf/blob/061e86d8f5e9/map.go#L790-L801
const (
	UpdateAny     MapUpdateFlags = iota
	UpdateNoExist MapUpdateFlags = 1 << (iota - 1)
	UpdateExist
	UpdateLock
)

func GetMap(name string) (Map, error) {
	ret := getMap(uint64(stringToBufPtr(name)))
	runtime.KeepAlive(name)
	if ret == 0 {
		return 0, fmt.Errorf("map %s not found", name)
	}
	return Map(ret), nil
}

func (m Map) Lookup(key any, value any) error {
	if reflect.TypeOf(value).Kind() != reflect.Pointer {
		return fmt.Errorf("value expected type *%T, got %T", value, value)
	}

	keyPtr, err := anytoBufPtr2(key)
	if err != nil {
		return err
	}

	valuePtr, err := anytoBufPtr2(value)
	if err != nil {
		return err
	}

	ret := mapLookup(uint32(m), uint64(keyPtr), uint64(valuePtr))
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	if ret != 0 {
		return fmt.Errorf("looking up map")
	}

	return nil
}

func (m Map) Put(key any, value any) error {
	return m.Update(key, value, 0)
}

func (m Map) Update(key any, value any, flags MapUpdateFlags) error {
	keyPtr, err := anytoBufPtr2(key)
	if err != nil {
		return err
	}

	valuePtr, err := anytoBufPtr2(value)
	if err != nil {
		return err
	}

	ret := mapUpdate(uint32(m), uint64(keyPtr), uint64(valuePtr), uint64(flags))
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	if ret != 0 {
		return fmt.Errorf("updating value in map")
	}
	return nil
}

func (m Map) Delete(key any) error {
	keyPtr, err := anytoBufPtr2(key)
	if err != nil {
		return err
	}

	ret := mapDelete(uint32(m), uint64(keyPtr))
	runtime.KeepAlive(key)
	if ret != 0 {
		return fmt.Errorf("deleting value in map")
	}
	return nil
}
