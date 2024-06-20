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
	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

//export gadgetInit
func gadgetInit() int {
	ds, err := api.GetDataSource("myds")
	if err != nil {
		api.Warnf("failed to get datasource: %v", err)
		return 1
	}

	type field struct {
		name string
		typ  api.FieldKind
		acc  api.Field
		val  any
	}

	fields := []*field{
		{"field_bool", api.Kind_Bool, 0, bool(true)},
		{"field_int8", api.Kind_Int8, 0, int8(-123)},
		{"field_int16", api.Kind_Int16, 0, int16(-25647)},
		{"field_int32", api.Kind_Int32, 0, int32(-535245564)},
		{"field_int64", api.Kind_Int64, 0, int64(-1234567890)},
		{"field_uint8", api.Kind_Uint8, 0, uint8(56)},
		{"field_uint16", api.Kind_Uint16, 0, uint16(12345)},
		{"field_uint32", api.Kind_Uint32, 0, uint32(1234567890)},
		{"field_uint64", api.Kind_Uint64, 0, uint64(1234567890123456)},
		{"field_float32", api.Kind_Float32, 0, float32(3.14159)},
		{"field_float64", api.Kind_Float64, 0, float64(3.14159265359)},
		{"field_string", api.Kind_String, 0, string("Hello, World!")},
		{"field_bytes", api.Kind_Bytes, 0, []byte{0x01, 0x02, 0x03, 0x04, 0x05}},
	}

	for _, f := range fields {
		acc, err := ds.AddField(f.name, f.typ)
		if err != nil {
			api.Warnf("failed to add field: %v", err)
			return 1
		}
		f.acc = acc
	}

	hostF, err := ds.GetField("host_field")
	if err != nil {
		api.Warnf("failed to get host field: %v", err)
		return 1
	}

	fields = append(fields, &field{"host_field", api.Kind_String, hostF, "LOCALHOST"})

	ds.Subscribe(func(source api.DataSource, data api.Data) {
		for _, f := range fields {
			switch f.typ {
			case api.Kind_Int8:
				f.acc.SetInt8(data, f.val.(int8))
			case api.Kind_Int16:
				f.acc.SetInt16(data, f.val.(int16))
			case api.Kind_Int32:
				f.acc.SetInt32(data, f.val.(int32))
			case api.Kind_Int64:
				f.acc.SetInt64(data, f.val.(int64))
			case api.Kind_Uint8:
				f.acc.SetUint8(data, f.val.(uint8))
			case api.Kind_Uint16:
				f.acc.SetUint16(data, f.val.(uint16))
			case api.Kind_Uint32:
				f.acc.SetUint32(data, f.val.(uint32))
			case api.Kind_Uint64:
				f.acc.SetUint64(data, f.val.(uint64))
			case api.Kind_Float32:
				f.acc.SetFloat32(data, f.val.(float32))
			case api.Kind_Float64:
				f.acc.SetFloat64(data, f.val.(float64))
			case api.Kind_String:
				f.acc.SetString(data, f.val.(string))
			case api.Kind_Bytes:
				f.acc.SetBytes(data, f.val.([]byte))
			}
		}
	}, 0)

	return 0
}

func main() {}
