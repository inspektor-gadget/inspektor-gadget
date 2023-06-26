// Copyright 2022-2023 The Inspektor Gadget authors
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
	"encoding/json"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
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
