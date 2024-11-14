// Copyright 2024-2025 The Inspektor Gadget authors
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
	"fmt"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

var (
	flamegraph   api.Field
	stacks       api.DataSource
	flamegraphDS api.DataSource
)

//go:wasmexport gadgetInit
func gadgetInit() int {
	// fgbool, err := api.GetParamValue("flamegraph")
	// if err != nil {
	// 	api.Errorf("getting flamegraph param: %v", err)
	// 	return 1
	// }
	// if fgbool != "true" {
	// 	api.Log(api.InfoLevel, "flamegraph not requested")
	// 	return 0
	// }

	var err error
	stacks, err = api.GetDataSource("stacks")
	if err != nil {
		api.Warnf("getting datasource stacks: %v", err)
		return 1
	}

	flamegraphDS, err = api.NewDataSource("flamegraph", api.DataSourceTypeSingle)
	if err != nil {
		return 1
	}
	flamegraph, err = flamegraphDS.AddField("text", api.Kind_String)
	if err != nil {
		return 1
	}

	// stacks.Unreference()
	return 0
}

//go:wasmexport gadgetPreStart
func gadgetPreStart() int {
	// get important fields
	commField, _ := stacks.GetField("proc.comm")
	containerNameField, _ := stacks.GetField("runtime.containerName")
	kernelStackField, _ := stacks.GetField("kernel_stack_id")
	userStackField, _ := stacks.GetField("user_stack_id")
	timeField, _ := stacks.GetField("time")

	stacks.Subscribe(func(source api.DataSource, data api.Data) {
		comm, _ := commField.String(data, 16)
		containerName, _ := containerNameField.String(data, 128)
		kernelStack, _ := kernelStackField.String(data, 128)
		userStack, _ := userStackField.String(data, 2048)
		time, _ := timeField.Uint64(data)

		ps, _ := flamegraphDS.NewPacketSingle()
		flamegraph.SetString(api.Data(ps), fmt.Sprintf("%s,%s,%s,%s %d\n", containerName, comm, userStack, kernelStack, time))
		flamegraphDS.EmitAndRelease(api.Packet(ps))
	}, 10000)

	return 0
}

func main() {}
