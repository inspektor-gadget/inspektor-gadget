// Copyright 2025 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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

//export gadgetPreStart
func gadgetPreStart() int {
	ds, err := api.GetDataSource("containers")
	if err != nil {
		api.Errorf("Failed to get data source: %v", err)
		return 1
	}

	eventTypeField, err := ds.GetField("event_type")
	if err != nil {
		api.Errorf("Failed to get field: %v", err)
		return 1
	}

	cgroupIDField, err := ds.GetField("cgroup_id")
	if err != nil {
		api.Errorf("Failed to get field: %v", err)
		return 1
	}

	mntnsIDField, err := ds.GetField("mntns_id")
	if err != nil {
		api.Errorf("Failed to get field: %v", err)
		return 1
	}

	nameField, err := ds.GetField("name")
	if err != nil {
		api.Errorf("Failed to get field: %v", err)
		return 1
	}

	ds.Subscribe(func(ds api.DataSource, data api.Data) {
		_, err := eventTypeField.String(data, api.DataSourceContainersEventTypeMaxSize)
		if err != nil {
			api.Errorf("getting event_type from corresponding field: %v", err)
			return
		}

		_, err = cgroupIDField.Uint64(data)
		if err != nil {
			api.Errorf("getting cgroup_id from corresponding field: %v", err)
			return
		}

		_, err = mntnsIDField.Uint64(data)
		if err != nil {
			api.Errorf("getting mntns_id from corresponding field: %v", err)
			return
		}

		_, err = nameField.String(data, 64)
		if err != nil {
			api.Errorf("getting name from corresponding field: %v", err)
			return
		}
	}, 0)

	return 0
}

func main() {}
