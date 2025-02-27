// Copyright 2025 The Inspektor Gadget authors
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
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

var (
	textds    api.DataSource
	textField api.Field
)

//export gadgetInit
func gadgetInit() int {
	var err error
	textds, err = api.NewDataSource("advise", api.DataSourceTypeSingle)
	if err != nil {
		api.Errorf("creating datasource: %s", err)
		return 1
	}

	textField, err = textds.AddField("text", api.Kind_String)
	if err != nil {
		api.Errorf("adding field: %s", err)
		return 1
	}

	return 0
}

//export gadgetPreStart
func gadgetPreStart() int {
	syscallds, err := api.GetDataSource("syscalls")
	if err != nil {
		api.Errorf("getting datasource: %s", err)
		return 1
	}

	syscallsF, err := syscallds.GetField("syscalls")
	if err != nil {
		api.Errorf("getting field: %s", err)
		return 1
	}

	mntnsidF, err := syscallds.GetField("mntns_id_raw")
	if err != nil {
		api.Errorf("getting field: %s", err)
		return 1
	}

	// do not check the error as this field is only used to provide a better
	// output. if the field is not present, the mntnsid will be used to name the
	// generated policy.
	containerF, _ := syscallds.GetField("runtime.containerName")

	err = syscallds.SubscribeArray(func(source api.DataSource, dataArr api.DataArray) error {
		// Get all fields sent by ebpf
		for j := 0; j < dataArr.Len(); j++ {
			data := dataArr.Get(j)

			scs, _ := syscallsF.Bytes(data)
			var containerName string
			if containerF != 0 {
				containerName, _ = containerF.String(data)
			}

			syscallStrings := make([]string, 0)
			for i := 0; i < len(scs); i++ {
				if scs[i] > 0 {
					syscallName, err := api.GetSyscallName(uint16(i))
					if err != nil {
						syscallName = fmt.Sprintf("unknown_syscall_%d", i)
					}
					syscallStrings = append(syscallStrings, syscallName)
				}
			}

			slices.Sort(syscallStrings)

			if containerName == "" {
				mntnsid, _ := mntnsidF.Uint64(data)
				containerName = fmt.Sprintf("mntnsid %d", mntnsid)
			}

			var out strings.Builder
			out.WriteString(fmt.Sprintf("// %s\n", containerName))
			jsonText, _ := json.MarshalIndent(map[string]any{
				"defaultAction": "SCMP_ACT_ERRNO",
				"architectures": []string{
					"SCMP_ARCH_X86_64",
					"SCMP_ARCH_X86",
					"SCMP_ARCH_X32",
				},
				"syscalls": syscallStrings,
			}, "", "  ")
			out.Write(jsonText)
			out.WriteRune('\n')

			nd, _ := textds.NewPacketSingle()
			textField.SetString(api.Data(nd), out.String())
			textds.EmitAndRelease(api.Packet(nd))
		}
		return nil
	}, 9999)
	if err != nil {
		api.Warnf("subscribing to syscalls: %s", err)
		return 1
	}
	return 0
}

func main() {}
