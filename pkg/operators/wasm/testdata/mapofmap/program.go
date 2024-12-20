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

//export gadgetInit
func gadgetInit() int {
	if api.GetFdFlag == api.UpdateLock {
		api.Errorf("GetFdFlag and UpdateLock must be different, got %d and %d", api.GetFdFlag, api.UpdateLock)
		return 1
	}

	return 0
}
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
	var val int32

	mapOfMap, err := api.GetMap(mapOfMapName)
	if err != nil {
		api.Errorf("%s map exists", mapOfMapName)
		return 1
	}

	mapName := "test_hash"
	hashMap, err := api.NewMap(api.MapSpec{
		Name:       mapName,
		Type:       api.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err != nil {
		api.Errorf("creating map %s", mapName)
		return 1
	}
	defer hashMap.Close()

	err = mapOfMap.Update(key, hashMap, api.GetFdFlag)
	if err != nil {
		api.Errorf("setting %s FD value for key %v in %s: %v", mapName, key, mapOfMapName, err)
		return 1
	}

	err = mapOfMap.Update(key, hashMap, 0)
	if err == nil {
		api.Errorf("updating %s, which type is BPF_MAP_TYPE_HASH_OF_MAPS, without GetFdFlag", mapOfMapName)
		return 1
	}

	err = mapOfMap.Lookup(key, &val)
	if err != nil {
		api.Errorf("no value found for key %v in %s", key, mapOfMapName)
		return 1
	}

	if val == 0 {
		api.Errorf("expected FD value to be different than 0")
		return 1
	}

	mapName = "test_array"
	arrayMap, err := api.NewMap(api.MapSpec{
		Name:       mapName,
		Type:       api.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err != nil {
		api.Errorf("creating map %s", mapName)
		return 1
	}
	defer arrayMap.Close()

	err = mapOfMap.Update(key, arrayMap, api.GetFdFlag)
	if err == nil {
		api.Errorf("should not be able setting %s FD value for key %v in %s", mapName, key, mapOfMapName)
		return 1
	}

	return 0
}

func main() {}
