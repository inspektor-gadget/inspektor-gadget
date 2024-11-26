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
	mapName := "test_map"

	_, err := api.GetMap(mapName)
	if err == nil {
		api.Errorf("%s map does not exist", mapName)
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

	mapName := "test_map"
	expectedVal := int32(42)
	newVal := int32(43)
	key := map_test_struct{a: 42, b: 42, c: 43}
	var val int32

	m, err := api.GetMap(mapName)
	if err != nil {
		api.Errorf("%s map exists", mapName)
		return 1
	}

	err = m.Put(key, expectedVal)
	if err != nil {
		api.Errorf("setting %v value for key %v in %s: %w", expectedVal, key, mapName, err)
		return 1
	}

	err = m.Lookup(key, &val)
	if err != nil {
		api.Errorf("no value found for key %v in %s", key, mapName)
		return 1
	}

	if val != expectedVal {
		api.Errorf("expected value %d, got %d", expectedVal, val)
		return 1
	}

	err = m.Lookup(key, val)
	if err == nil {
		api.Errorf("lookup only accepts pointer for value argument")
		return 1
	}

	err = m.Update(key, newVal, api.UpdateExist)
	if err != nil {
		api.Errorf("updating value for key %v in %s", key, mapName)
		return 1
	}

	err = m.Lookup(key, &val)
	if err != nil {
		api.Errorf("no value found for key %v in %s", key, mapName)
		return 1
	}

	if val != newVal {
		api.Errorf("expected value %d, got %d", newVal, val)
		return 1
	}

	err = m.Delete(key)
	if err != nil {
		api.Errorf("deleting value for key %v in %s", key, mapName)
		return 1
	}

	err = m.Put(key, val)
	if err != nil {
		api.Errorf("setting %v value for key %v in %s", val, key, mapName)
		return 1
	}

	err = m.Update(key, newVal, api.UpdateNoExist)
	if err == nil {
		api.Errorf("cannot update value for key %v in %s as it is not already present", key, mapName)
		return 1
	}

	err = m.Update(key, newVal, api.UpdateExist)
	if err != nil {
		api.Errorf("cannot update value for key %v in %s as it is already present", key, mapName)
		return 1
	}

	err = m.Delete(key)
	if err != nil {
		api.Errorf("deleting value for key %v in %s", key, mapName)
		return 1
	}

	err = m.Delete(key)
	if err == nil {
		api.Errorf("there is value for key %v in %s", key, mapName)
		return 1
	}

	err = m.Close()
	if err == nil {
		api.Errorf("cannot close a map got with GetMap()")
		return 1
	}

	mapSpec := api.MapSpec{
		Name:       "map_test",
		Type:       api.Hash,
		KeySize:    uint32(4),
		ValueSize:  uint32(4),
		MaxEntries: 1,
	}

	newMap, err := api.NewMap(mapSpec)
	if err != nil {
		api.Errorf("creating map %s", mapSpec.Name)
	}
	defer newMap.Close()

	k := int32(42)
	val = int32(43)
	err = newMap.Put(k, val)
	if err != nil {
		api.Errorf("setting %v value for key %v in %s", val, k, mapSpec.Name)
		return 1
	}

	err = newMap.Lookup(k, &val)
	if err != nil {
		api.Errorf("no value found for key %v in %s", k, mapSpec.Name)
		return 1
	}

	expectedVal = int32(43)
	if val != expectedVal {
		api.Errorf("expected value %d, got %d", expectedVal, val)
		return 1
	}

	k = int32(0xdead)
	val = int32(0xcafe)
	err = newMap.Put(k, val)
	if err == nil {
		api.Errorf("map %s has one max entry, trying to put two", mapSpec.Name)
		return 1
	}

	return 0
}

func main() {}
