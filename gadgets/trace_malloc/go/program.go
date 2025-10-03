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
	"fmt"
	"strings"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

var (
	textds    api.DataSource
	textField api.Field
)

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	var err error
	textds, err = api.NewDataSource("flamegraph", api.DataSourceTypeSingle)
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
	syscallds, err := api.GetDataSource("allocs")
	if err != nil {
		api.Errorf("getting datasource: %s", err)
		return 1
	}

	symbolsF, err := syscallds.GetField("ustack.symbols")
	if err != nil {
		api.Errorf("getting symbols field: %s", err)
		return 1
	}

	countF, err := syscallds.GetField("count")
	if err != nil {
		api.Errorf("getting count field: %s", err)
		return 1
	}

	commF, err := syscallds.GetField("proc.comm")
	if err != nil {
		api.Errorf("getting comm field: %s", err)
		return 1
	}

	err = syscallds.SubscribeArray(func(source api.DataSource, dataArr api.DataArray) error {
		// Get all fields sent by ebpf

		var out strings.Builder

		for j := 0; j < dataArr.Len(); j++ {
			data := dataArr.Get(j)

			symbols, err := symbolsF.String(data, 4096)
			if err != nil {
				api.Warnf("reading symbols: %s", err)
				continue
			}

			// invert symbols

			symbolsPart := strings.Split(symbols, "; ")
			for i, j := 0, len(symbolsPart)-1; i < j; i, j = i+1, j-1 {
				symbolsPart[i], symbolsPart[j] = symbolsPart[j], symbolsPart[i]

			}

			comm, err := commF.String(data, 256)
			if err != nil {
				api.Warnf("reading comm: %s", err)
				continue
			}

			symbols = strings.Join(symbolsPart, "; ")

			// append process name to understand what process are those calls comming from
			symbols = comm + /*";" + */ symbols

			//api.Infof("symbols: %s", symbols)

			count, err := countF.Uint64(data)
			if err != nil {
				api.Warnf("reading count: %s", err)
				continue
			}

			//api.Infof("count: %d", count)

			out.WriteString(fmt.Sprintf("%s %d\n", symbols, count))
		}

		nd, err := textds.NewPacketSingle()
		if err != nil {
			api.Warnf("creating new packet: %s", err)
			return nil
		}
		textField.SetString(api.Data(nd), out.String())
		textds.EmitAndRelease(api.Packet(nd))

		return nil
	}, 9999)
	if err != nil {
		api.Warnf("subscribing to syscalls: %s", err)
		return 1
	}
	return 0
}

func main() {}
