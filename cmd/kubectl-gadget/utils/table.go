// Copyright 2019-2021 The Inspektor Gadget authors
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

package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

var wellknownColLens = map[string]int{
	"namespace": 16,
	"node":      16,
	"pod":       16,
	"container": 16,
	"pcomm":     20,
	"comm":      20,
	"pid":       8,
	"ppid":      8,
}

type TableFormater struct {
	colList []string
	colLens []int
}

func NewTableFormater(colList []string, colLensUser map[string]int) *TableFormater {
	if colList == nil || colLensUser == nil {
		return nil
	}
	colLens := make([]int, len(colList))

	for i, col := range colList {
		// try lengths passed by the user first
		length, ok := colLensUser[col]
		if !ok {
			// try wellknown lengths after
			length, ok = wellknownColLens[col]
			if !ok {
				// default to len of column name
				length = len(col) + 1
			}
		}

		colLens[i] = length
	}

	return &TableFormater{
		colList: colList,
		colLens: colLens,
	}
}

func (t *TableFormater) GetHeader() string {
	var ret string

	for i, col := range t.colList {
		ret += fmt.Sprintf("%-*s", t.colLens[i], strings.ToUpper(col))
	}

	return ret
}

// toString converts val to its string representation. Elements in a slice are
// separated by an empty space.
func toString(val interface{}) string {
	switch val.(type) {
	case []interface{}:
		var ret string
		for idx, i := range val.([]interface{}) {
			ret += fmt.Sprintf("%v", i)

			if idx < len(val.([]interface{}))-1 {
				ret += " "
			}
		}
		return ret
	default:
		return fmt.Sprintf("%v", val)
	}
}

func (t *TableFormater) GetTransformFunc() func(string) string {
	return func(line string) string {
		event := make(map[string]interface{})

		err := json.Unmarshal([]byte(line), &event)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s", WrapInErrUnmarshalOutput(err, line))
			return ""
		}

		var ret string

		for i, col := range t.colList {
			len := t.colLens[i]

			val, ok := event[col]
			if !ok {
				ret += fmt.Sprintf("%-*s ", len-1, "<>")
				continue
			}
			ret += fmt.Sprintf("%-*s ", len-1, toString(val))
		}

		return ret
	}
}
