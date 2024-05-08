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

import api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"

//export gadgetInit
func gadgetInit() int {
	ds, err := api.GetDataSource("myds")
	if err != nil {
		api.Warnf("failed to get datasource: %v", err)
		return 1
	}

	fooF, err := ds.GetField("foo")
	if err != nil {
		api.Warnf("failed to get host field: %v", err)
		return 1
	}

	err = ds.SubscribeArray(func(source api.DataSource, dataArray api.DataArray) error {
		l := dataArray.Len()
		if l != 10 {
			api.Warnf("bad length: got: %d, expected: 10", l)
			panic("bad length")
		}

		// Update value of first 10 elements
		for i := 0; i < 10; i++ {
			data := dataArray.Get(i)
			val, err := fooF.Uint32(data)
			if err != nil {
				api.Warnf("failed to get field: %v", err)
				panic("failed to get field")
			}
			fooF.SetUint32(data, val*uint32(i))
		}

		// Add 5 additional elements
		for i := 10; i < 15; i++ {
			data := dataArray.New()
			fooF.SetUint32(data, 424143*uint32(i))
			dataArray.Append(data)
		}

		return nil
	}, 0)

	if err != nil {
		api.Warnf("failed to subscribe: %v", err)
		return 1
	}

	return 0
}

func main() {}
