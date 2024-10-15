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
	"runtime"

	"github.com/cilium/ebpf"
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

func GetMap(name string) (Map, error) {
	ret := getMap(uint64(stringToBufPtr(name)))
	runtime.KeepAlive(name)
	if ret == 0 {
		return 0, fmt.Errorf("map %s not found", name)
	}
	return Map(ret), nil
}

func (m Map) Lookup(key any, value any) error {
	keyPtr := anytoBufPtr(key)
// 	defer keyPtr.free()

	valuePtr := anytoBufPtr(value)
// 	defer valuePtr.free()

	ret := mapLookup(uint32(m), uint64(keyPtr), uint64(valuePtr))
	if ret == 0 {
		return fmt.Errorf("lookuping map")
	}
	return nil
}

func (m Map) Put(key any, value any) error {
	keyPtr := anytoBufPtr(key)
// 	defer keyPtr.free()

	valuePtr := anytoBufPtr(value)
// 	defer valuePtr.free()

	ret := mapUpdate(uint32(m), uint64(keyPtr), uint64(valuePtr), uint64(ebpf.UpdateAny))
	if ret == 0 {
		return fmt.Errorf("putting value in map")
	}
	return nil
}

func (m Map) Update(key any, value any, flags ebpf.MapUpdateFlags) error {
	keyPtr := anytoBufPtr(key)
// 	defer keyPtr.free()

	valuePtr := anytoBufPtr(value)
// 	defer valuePtr.free()

	ret := mapUpdate(uint32(m), uint64(keyPtr), uint64(valuePtr), uint64(flags))
	if ret == 0 {
		return fmt.Errorf("updating value in map")
	}
	return nil
}

func (m Map) Delete(key any) error {
	keyPtr := anytoBufPtr(key)
// 	defer keyPtr.free()

	ret := mapDelete(uint32(m), uint64(keyPtr))
	if ret == 0 {
		return fmt.Errorf("updating value in map")
	}
	return nil
}
