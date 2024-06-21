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
	"fmt"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

func getCallStr(op int32, source string, target string, fs string, flags string, data string, ret int32) string {
	switch op {
	case 0:
		format := `mount("%s", "%s", "%s", %s, "%s") = %d`
		return fmt.Sprintf(format, source, target, fs, flags, data, ret)
	case 1:
		format := `umount("%s", %s) = %d`
		return fmt.Sprintf(format, target, flags, ret)
	}

	return ""
}

//export gadgetInit
func gadgetInit() int {
	ds, err := api.GetDataSource("mount")
	if err != nil {
		api.Warnf("failed to get datasource: %s", err)
		return 1
	}

	// Fields needed by this layer
	opRawField, err := ds.GetField("op_raw")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}

	srcField, err := ds.GetField("src")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}

	destField, err := ds.GetField("dest")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}

	fsField, err := ds.GetField("fs")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}

	dataField, err := ds.GetField("data")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}

	retField, err := ds.GetField("ret")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}

	flagsField, err := ds.GetField("flags")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}

	// Field provided by this layer

	callField, err := ds.AddField("call", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	ds.Subscribe(func(source api.DataSource, data api.Data) {
		flags, _ := flagsField.String(data)
		opRaw, _ := opRawField.Int32(data)
		src, _ := srcField.String(data)
		dest, _ := destField.String(data)
		fs, _ := fsField.String(data)
		dataStr, _ := dataField.String(data)
		ret, _ := retField.Int32(data)

		callField.SetString(data, getCallStr(opRaw, src, dest, fs, flags, dataStr, ret))
	}, 0)

	return 0
}

func main() {}
