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

type SeccompProfile struct {
	DefaultAction string     `json:"defaultAction"`
	Architectures []string   `json:"architectures"`
	Syscalls      []Syscalls `json:"syscalls"`
}

type Syscalls struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
}

//go:wasmexport gadgetInit
func gadgetInit() int32 {
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

//go:wasmexport gadgetPreStart
func gadgetPreStart() int32 {
	syscallds, err := api.GetDataSource("syscalls")
	if err != nil {
		api.Errorf("getting datasource: %s", err)
		return 1
	}

	syscallsF, err := syscallds.GetField("syscalls")
	if err != nil {
		api.Errorf("getting syscalls field: %s", err)
		return 1
	}

	containerF, err := syscallds.GetField("runtime.containerName")
	if err != nil {
		api.Errorf("getting runtime.containerName field: %s", err)
		return 1
	}

	// keep in sync with SYSCALLS_MAP_VALUE_SIZE in program.bpf.c
	syscallsBuffer := make([]byte, 500+1)

	err = syscallds.SubscribeArray(func(source api.DataSource, dataArr api.DataArray) error {
		// Get all fields sent by ebpf
		for j := 0; j < dataArr.Len(); j++ {
			data := dataArr.Get(j)

			if _, err := syscallsF.Bytes(data, syscallsBuffer); err != nil {
				api.Warnf("reading syscalls: %s", err)
				continue
			}

			containerName, err := containerF.String(data, 512)
			if err != nil {
				api.Warnf("reading container name: %s", err)
				continue
			}

			// only generate policy for known containers
			if containerName == "" {
				continue
			}

			syscallStrings := make([]string, 0)
			for i := range syscallsBuffer {
				if syscallsBuffer[i] > 0 {
					syscallName, err := api.GetSyscallName(uint16(i))
					if err != nil {
						syscallName = fmt.Sprintf("unknown_syscall_%d", i)
					}
					syscallStrings = append(syscallStrings, syscallName)
				}
			}

			slices.Sort(syscallStrings)

			var out strings.Builder
			out.WriteString(fmt.Sprintf("// %s\n", containerName))

			profile := SeccompProfile{
				DefaultAction: "SCMP_ACT_ERRNO",
				Architectures: []string{
					"SCMP_ARCH_X86_64",
					"SCMP_ARCH_X86",
					"SCMP_ARCH_X32",
				},
				Syscalls: []Syscalls{
					{
						Names:  syscallStrings,
						Action: "SCMP_ACT_ALLOW",
					},
				},
			}

			jsonText, _ := json.MarshalIndent(profile, "", "  ")
			out.Write(jsonText)
			out.WriteRune('\n')

			nd, err := textds.NewPacketSingle()
			if err != nil {
				api.Warnf("creating new packet: %s", err)
				continue
			}
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
