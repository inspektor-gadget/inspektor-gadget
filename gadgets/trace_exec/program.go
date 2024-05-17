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
	"strings"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

//export gadgetInit
func gadgetInit() int {
	ds, err := api.GetDataSource("exec")
	if err != nil {
		api.Warnf("failed to get datasource: %s", err)
		return 1
	}

	argsF, err := ds.GetField("args")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}

	argsSize, err := ds.GetField("args_size")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}

	argsCount, err := ds.GetField("args_count")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}

	ds.Subscribe(func(source api.DataSource, data api.Data) {
		// Get all fields sent by ebpf
		payload, _ := argsF.Bytes(data)
		argsSize, _ := argsSize.Uint32(data)
		argsCount, _ := argsCount.Int32(data)

		args := []string{}
		count := 0
		buf := []byte{}

		for i := 0; i < int(argsSize) && count < int(argsCount); i++ {
			c := payload[i]
			if c == 0 {
				args = append(args, string(buf))
				count = 0
				buf = []byte{}
			} else {
				buf = append(buf, c)
			}
		}

		// TODO: The datasource doesn't support arrays yet, hence we have to
		// join the args in a single string. This could be wrong as it's
		// possible to execute a process with arguments that contain spaces.
		argsF.SetString(data, strings.Join(args, " "))
	}, 0)

	return 0
}

func main() {}
