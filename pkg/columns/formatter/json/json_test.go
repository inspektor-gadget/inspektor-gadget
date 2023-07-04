// Copyright 2023 The Inspektor Gadget authors
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

package json

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"testing"
	"unsafe"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testStruct struct {
	Name     string  `column:"name,width:10"`
	Age      uint    `column:"age,width:4,align:right,fixed"`
	Size     float32 `column:"size,width:6,precision:2,align:right"`
	Balance  int     `column:"balance,width:8,align:right"`
	CanDance bool    `column:"canDance,width:8"`
}

var testEntries = []*testStruct{
	{"Alice", 32, 1.74, 1000, true},
	{"Bob", 26, 1.73, -200, true},
	{"Eve", 99, 5.12, 1000000, false},
	nil,
}

var testColumns = columns.MustCreateColumns[testStruct]().GetColumnMap()

func TestJSONFormatter_FormatEntry(t *testing.T) {
	expected := []string{
		"{\"name\": \"Alice\", \"age\": 32, \"size\": 1.74, \"balance\": 1000, \"canDance\": true}",
		"{\"name\": \"Bob\", \"age\": 26, \"size\": 1.73, \"balance\": -200, \"canDance\": true}",
		"{\"name\": \"Eve\", \"age\": 99, \"size\": 5.12, \"balance\": 1000000, \"canDance\": false}",
		"",
	}
	formatter := NewFormatter(testColumns)
	for i, entry := range testEntries {
		if res := formatter.FormatEntry(entry); res != expected[i] {
			t.Errorf("got %s, expected %s", res, expected[i])
		}
	}
}

func TestJSONFormatter_PrettyFormatEntry(t *testing.T) {
	expected := []string{
		"{\n  \"name\": \"Alice\",\n  \"age\": 32,\n  \"size\": 1.74,\n  \"balance\": 1000,\n  \"canDance\": true\n}",
		"{\n  \"name\": \"Bob\",\n  \"age\": 26,\n  \"size\": 1.73,\n  \"balance\": -200,\n  \"canDance\": true\n}",
		"{\n  \"name\": \"Eve\",\n  \"age\": 99,\n  \"size\": 5.12,\n  \"balance\": 1000000,\n  \"canDance\": false\n}",
		"",
	}
	formatter := NewFormatter(testColumns, WithPrettyPrint())
	for i, entry := range testEntries {
		if res := formatter.FormatEntry(entry); res != expected[i] {
			t.Errorf("got %s, expected %s", res, expected[i])
		}
	}
}

func BenchmarkFormatter(b *testing.B) {
	b.StopTimer()
	formatter := NewFormatter(testColumns)
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		formatter.FormatEntry(testEntries[n%len(testEntries)])
	}
}

func BenchmarkNative(b *testing.B) {
	b.StopTimer()
	// do a dry-run to enable caching
	json.Marshal(testEntries[0])
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		json.Marshal(testEntries[n%len(testEntries)])
	}
}

func TestDynamicFields(t *testing.T) {
	// Write the data in its binary representation to a buffer
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, []uint8("foobar"))
	require.NoError(t, err)
	err = binary.Write(buf, binary.LittleEndian, int32(1234567890))
	require.NoError(t, err)
	err = binary.Write(buf, binary.LittleEndian, true)
	require.NoError(t, err)

	fields := []columns.DynamicField{{
		Attributes: &columns.Attributes{
			Name:    "str",
			Width:   columns.GetDefault().DefaultWidth,
			Visible: true,
			Order:   0,
		},
		Type:   reflect.TypeOf([6]uint8{}),
		Offset: 0,
	}, {
		Attributes: &columns.Attributes{
			Name:    "int32",
			Width:   columns.GetDefault().DefaultWidth,
			Visible: true,
			Order:   1,
		},
		Type:   reflect.TypeOf(int32(0)),
		Offset: 6,
	}, {
		Attributes: &columns.Attributes{
			Name:    "bool",
			Width:   columns.GetDefault().DefaultWidth,
			Visible: true,
			Order:   2,
		},
		Type:   reflect.TypeOf(true),
		Offset: 10,
	}}

	type empty struct{}
	cols := columns.MustCreateColumns[empty]()
	cols.AddFields(fields, func(ev *empty) unsafe.Pointer {
		bytes := buf.Bytes()
		return unsafe.Pointer(&bytes[0])
	})
	formatter := NewFormatter[empty](cols.GetColumnMap())
	assert.Equal(t, `{"str": "foobar", "int32": 1234567890, "bool": true}`, formatter.FormatEntry(&empty{}))
}
