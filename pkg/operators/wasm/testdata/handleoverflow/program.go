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
	"errors"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	ds, err := api.GetDataSource("myds")
	if err != nil {
		return 1
	}

	inField, err := ds.GetField("in")
	if err != nil {
		return 1
	}

	outField, err := ds.GetField("out")
	if err != nil {
		return 1
	}

	// Create dummy packets, indirectly increasing the internal handler index sequence.
	// This forces `lastHandleIndex` higher than maxHandleIndexValue.
	for range 70000 {
		packet, err := ds.NewPacketArray()
		if err != nil {
			return 1
		}
		if err := ds.Release(api.Packet(packet)); err != nil {
			return 1
		}
	}

	// Simple callback, should continue to work as expected after handle index surpasses maxHandleIndexValue.
	if err := ds.SubscribeArray(func(source api.DataSource, dataArray api.DataArray) error {
		var errs error
		for i := range dataArray.Len() {
			data := dataArray.Get(i)
			val, err := inField.Uint32(data)
			if err != nil {
				errs = errors.Join(errs, err)
				continue
			}
			if err := outField.SetUint32(data, val*2); err != nil {
				errs = errors.Join(errs, err)
				continue
			}
		}
		if errs != nil {
			api.Warnf("Errors processing data array: %v", errs.Error())
			return errs
		}
		return nil
	}, 0); err != nil {
		api.Warnf("failed to subscribe: %v", err)
		return 1
	}

	return 0
}

func main() {}
