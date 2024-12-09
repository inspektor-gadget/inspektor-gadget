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
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

var (
	sc             api.DataSource
	syscallds      api.DataSource
	textds         api.DataSource
	textField      api.Field
	syscallMapping map[uint64]string
)

//export gadgetPreStart
func gadgetPreStart() int {
	syscallMapping = make(map[uint64]string)

	scStringField, err := sc.GetField("syscall")
	if err != nil {
		api.Warnf("getting syscall text field (enricher inactive?)")
		return 1
	}

	scIntField, err := sc.GetField("syscall_raw")
	if err != nil {
		api.Warnf("getting syscall int field")
		return 1
	}

	sc.Unreference() // probably too late

	sc.Subscribe(func(ds api.DataSource, data api.Data) {
		intVal, _ := scIntField.Uint64(data)
		stringVal, _ := scStringField.String(data)
		syscallMapping[intVal] = strings.ToLower(strings.TrimPrefix(stringVal, "SYS_"))
	}, 10000)

	parr, _ := sc.NewPacketArray()
	arr := api.DataArray(parr)
	for i := 0; i <= 500; i++ {
		data := arr.New()
		scIntField.SetUint64(data, uint64(i))
		arr.Append(data)
	}
	sc.EmitAndRelease(api.Packet(parr))

	syscalls, err := syscallds.GetField("syscalls")
	if err != nil {
		api.Warnf("getting field: %s", err)
		return 1
	}

	mntnsidField, err := syscallds.GetField("mntns_id_raw")
	if err != nil {
		api.Warnf("getting field: %s", err)
		return 1
	}

	container, err := syscallds.GetField("runtime.containerName")
	if err != nil {
		api.Warnf("getting field: %s", err)
		return 1
	}

	err = syscallds.SubscribeArray(func(source api.DataSource, dataArr api.DataArray) error {
		// Get all fields sent by ebpf
		for j := 0; j < dataArr.Len(); j++ {
			data := dataArr.Get(j)

			mntnsid, _ := mntnsidField.Uint64(data)
			if mntnsid == 0 {
				// this is the zero mntnsid template, we don't need that
				continue
			}

			scs, _ := syscalls.Bytes(data)
			containerName, _ := container.String(data)

			syscallStrings := make([]string, 0)
			for i := 0; i < len(scs); i++ {
				if scs[i] > 0 {
					syscallName, ok := syscallMapping[uint64(i)]
					if !ok {
						syscallName = fmt.Sprintf("unknown_syscall_%d", i)
					}
					syscallStrings = append(syscallStrings, syscallName)
				}
			}

			slices.Sort(syscallStrings)

			if containerName == "" {
				switch mntnsid {
				case 1:
					containerName = "host"
				default:
					containerName = fmt.Sprintf("mntnsid %d", mntnsid)
				}
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

//export gadgetInit
func gadgetInit() int {
	var err error
	// We need syscall id to name mapping; this is an ugly way to get it:
	sc, err = api.NewDataSource("syscallconv", api.DataSourceTypeArray)
	if err != nil {
		api.Warnf("creating syscalls data source %v", err)
		return 1
	}

	scField, err := sc.AddField("syscall_raw", api.Kind_Uint64)
	if err != nil {
		api.Warnf("creating syscall_raw field %v", err)
		return 1
	}
	scField.AddTag("type:gadget_syscall")

	// We'll read the input from the eBPF source, emit
	syscallds, err = api.GetDataSource("syscalls")
	if err != nil {
		api.Warnf("getting datasource: %s", err)
		return 1
	}
	// ds.Unreference()

	textds, _ = api.NewDataSource("advise", api.DataSourceTypeSingle)
	textField, _ = textds.AddField("text", api.Kind_String)

	return 0
}

func main() {}
