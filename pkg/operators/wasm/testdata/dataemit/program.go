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
	oldDs, err := api.GetDataSource("old_ds")
	if err != nil {
		api.Warnf("failed to get datasource: %v", err)
		return 1
	}
	fooF, err := oldDs.GetField("foo")
	if err != nil {
		api.Warnf("failed to get host field: %v", err)
		return 1
	}

	// Creating a new data source with a field named "bar"
	newDs, err := api.NewDataSource("new_ds", api.DataSourceTypeSingle)
	if err != nil {
		api.Warnf("failed to create datasource: %s", err)
		return 1
	}
	barF, err := newDs.AddField("bar", api.Kind_Uint32)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	err = oldDs.Subscribe(func(source api.DataSource, data api.Data) {
		val, err := fooF.Uint32(data)
		if err != nil {
			api.Warnf("failed to get field: %v", err)
			panic("failed to get field")
		}
		// Our new data source will emit only even values multiplied by 5
		if val%2 == 0 {
			packet, err := newDs.NewPacketSingle()
			if err != nil {
				api.Warnf("failed to create new packet: %s", err)
				panic("failed to create new packet")
			}
			barF.SetUint32(api.Data(packet), val*5)
			newDs.EmitAndRelease(api.Packet(packet))
		}
	}, 0)

	if err != nil {
		api.Warnf("failed to subscribe: %v", err)
		return 1
	}

	return 0
}

// The main function is not used, but it's still required by the compiler
func main() {}
