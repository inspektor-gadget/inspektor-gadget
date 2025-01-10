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

package main

import (
	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

//export gadgetStart
func gadgetStart() int {
	type map_test_struct struct {
		a int32
		b int32
		c int8
		_ [3]int8
	}

	mapOfMapName := "map_of_map"
	key := map_test_struct{a: 42, b: 42, c: 43}
	var innerMap api.Map

	mapOfMap, err := api.GetMap(mapOfMapName)
	if err != nil {
		api.Errorf("%s map must exist", mapOfMapName)
		return 1
	}

	hashMapName := "test_hash"
	hashMap, err := api.NewMap(api.MapSpec{
		Name:       hashMapName,
		Type:       api.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err != nil {
		api.Errorf("creating map %s", hashMapName)
		return 1
	}
	defer hashMap.Close()

	err = mapOfMap.Put(key, hashMap)
	if err != nil {
		api.Errorf("setting %s inner map value for key %v in %s: %v", hashMapName, key, mapOfMapName, err)
		return 1
	}

	err = mapOfMap.Lookup(key, &innerMap)
	if err != nil {
		api.Errorf("no value found for key %v in %s", key, mapOfMapName)
		return 1
	}

	if uint32(innerMap) == 0 {
		api.Errorf("expected handle to be different than 0")
		return 1
	}

	if uint32(innerMap) == uint32(hashMap) {
		api.Errorf("expected handle to be different than hashMap")
		return 1
	}

	err = innerMap.Put(uint32(42), uint32(43))
	if err != nil {
		api.Errorf("putting value in inner map %s: %v", hashMapName, err)
		return 1
	}

	err = mapOfMap.Delete(key)
	if err != nil {
		api.Errorf("deleting map %s", hashMap)
		return 1
	}

	return 0
}

func main() {}
