// Copyright 2022 The Inspektor Gadget authors
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
	"fmt"
	"testing"
)

func TestBaseParser(t *testing.T) {
	table := []struct {
		description    string
		columnsWidth   map[string]int
		useTabs        bool
		outputConfig   *OutputConfig
		expectedResult string
	}{
		{
			description:  "empty CustomColumns",
			outputConfig: &OutputConfig{},
		},
		{
			description: "none valid column",
			outputConfig: &OutputConfig{
				CustomColumns: []string{"abc"},
			},
			columnsWidth: map[string]int{
				"xyz": 0,
			},
		},
		{
			description: "ignore invalid column using width",
			outputConfig: &OutputConfig{
				CustomColumns: []string{"abc", "xyz"},
			},
			columnsWidth: map[string]int{
				"xyz": -10,
			},
			useTabs:        false,
			expectedResult: fmt.Sprintf("%-10s ", "XYZ"),
		},
		{
			description: "ignore invalid column using tabs",
			outputConfig: &OutputConfig{
				CustomColumns: []string{"abc", "xyz"},
			},
			columnsWidth: map[string]int{
				"xyz": 0,
			},
			useTabs:        true,
			expectedResult: fmt.Sprintf("%s\t", "XYZ"),
		},
		{
			description: "ignore multiple invalid columns using width",
			outputConfig: &OutputConfig{
				CustomColumns: []string{"abc", "dfe", "rst", "xyz"},
			},
			columnsWidth: map[string]int{
				"xyz": -10,
				"dfe": -5,
			},
			useTabs:        false,
			expectedResult: fmt.Sprintf("%-5s %-10s ", "DFE", "XYZ"),
		},
		{
			description: "ignore multiple invalid column using tabs",
			outputConfig: &OutputConfig{
				CustomColumns: []string{"abc", "dfe", "rst", "xyz"},
			},
			columnsWidth: map[string]int{
				"xyz": 0,
				"dfe": 0,
			},
			useTabs:        true,
			expectedResult: fmt.Sprintf("%s\t%s\t", "DFE", "XYZ"),
		},
		{
			description: "ignore columnWidth when using tabs",
			outputConfig: &OutputConfig{
				CustomColumns: []string{"dfe", "xyz"},
			},
			columnsWidth: map[string]int{
				"xyz": -5,
				"dfe": -10,
			},
			useTabs:        true,
			expectedResult: fmt.Sprintf("%s\t%s\t", "DFE", "XYZ"),
		},
		{
			description: "normal case using width",
			outputConfig: &OutputConfig{
				CustomColumns: []string{"abc", "dfe", "rst", "xyz"},
			},
			columnsWidth: map[string]int{
				"abc": -7,
				"dfe": -5,
				"rst": -1,
				"xyz": -10,
			},
			useTabs:        false,
			expectedResult: fmt.Sprintf("%-7s %-5s %-1s %-10s ", "ABC", "DFE", "RST", "XYZ"),
		},
		{
			description: "normal case using tabs",
			outputConfig: &OutputConfig{
				CustomColumns: []string{"abc", "dfe", "rst", "xyz"},
			},
			columnsWidth: map[string]int{
				"abc": 0,
				"dfe": 0,
				"rst": 0,
				"xyz": 0,
			},
			useTabs:        true,
			expectedResult: fmt.Sprintf("%s\t%s\t%s\t%s\t", "ABC", "DFE", "RST", "XYZ"),
		},
	}

	for i, entry := range table {
		p := NewBaseParser(entry.columnsWidth, entry.useTabs, entry.outputConfig)
		result := p.BuildColumnsHeader()
		if result != entry.expectedResult {
			t.Fatalf("Failed test %q (index %d): result %q expected %q",
				entry.description, i, result, entry.expectedResult)
		}
	}
}
