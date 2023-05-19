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

package group

import (
	"reflect"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
)

func TestGroupSum(t *testing.T) {
	type Embedded struct {
		EmbeddedInt   int64   `column:"embeddedInt,group:sum"`
		EmbeddedFloat float64 `column:"embeddedFloat,group:sum"`
	}
	type testStruct struct {
		Name      string  `column:"name"`
		Int       int64   `column:"int,group:sum"`
		Uint      uint64  `column:"uint,group:sum"`
		Float     float64 `column:"float,group:sum"`
		Secondary int     `column:"secondary"`
		Embedded
	}
	type testDefinition struct {
		Name           string
		GroupBy        []string
		Input          []*testStruct
		ExpectedResult []*testStruct
		ExpectError    bool
	}

	entries := []*testStruct{
		{Name: "a", Int: 1, Float: 1, Uint: 1, Secondary: 1, Embedded: Embedded{EmbeddedInt: 1, EmbeddedFloat: 1}},
		{Name: "a", Int: 1, Float: 1, Uint: 1, Secondary: 2, Embedded: Embedded{EmbeddedInt: 1, EmbeddedFloat: 1}},
		{Name: "b", Int: 2, Float: 2, Uint: 2, Secondary: 2, Embedded: Embedded{EmbeddedInt: 2, EmbeddedFloat: 2}},
		{Name: "b", Int: 2, Float: 2, Uint: 2, Secondary: 3, Embedded: Embedded{EmbeddedInt: 2, EmbeddedFloat: 2}},
		nil,
	}

	tests := []testDefinition{
		{
			Name:    "GroupAll",
			GroupBy: []string{""},
			Input:   entries,
			ExpectedResult: []*testStruct{
				{
					Name:      "a",
					Int:       6,
					Uint:      6,
					Float:     6,
					Secondary: 1,
					Embedded: Embedded{
						EmbeddedInt:   6,
						EmbeddedFloat: 6,
					},
				},
			},
		},
		{
			Name:    "GroupByColumn",
			GroupBy: []string{"name"},
			Input:   entries,
			ExpectedResult: []*testStruct{
				{
					Name:      "a",
					Int:       2,
					Uint:      2,
					Float:     2,
					Secondary: 1,
					Embedded: Embedded{
						EmbeddedInt:   2,
						EmbeddedFloat: 2,
					},
				},
				{
					Name:      "b",
					Int:       4,
					Uint:      4,
					Float:     4,
					Secondary: 2,
					Embedded: Embedded{
						EmbeddedInt:   4,
						EmbeddedFloat: 4,
					},
				},
			},
		},
		{
			Name:    "GroupByMultipleColumn",
			GroupBy: []string{"secondary", "name"},
			Input:   entries,
			ExpectedResult: []*testStruct{
				{
					Name:      "a",
					Int:       4,
					Uint:      4,
					Float:     4,
					Secondary: 1,
					Embedded: Embedded{
						EmbeddedInt:   4,
						EmbeddedFloat: 4,
					},
				},
				{
					Name:      "b",
					Int:       2,
					Uint:      2,
					Float:     2,
					Secondary: 3,
					Embedded: Embedded{
						EmbeddedInt:   2,
						EmbeddedFloat: 2,
					},
				},
			},
		},
		{
			Name:           "InvalidColumn",
			GroupBy:        []string{"foobar"},
			Input:          entries,
			ExpectedResult: nil,
			ExpectError:    true,
		},
		{
			Name:           "NilArray",
			GroupBy:        []string{"name"},
			Input:          nil,
			ExpectedResult: nil,
			ExpectError:    false,
		},
	}

	cols, err := columns.NewColumns[testStruct]()
	if err != nil {
		t.Errorf("Failed to initialize: %v", err)
	}

	cmap := cols.GetColumnMap()

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			result, err := GroupEntries(cmap, test.Input, test.GroupBy)

			if err != nil && !test.ExpectError {
				t.Errorf("While grouping: %v", err)
			}
			if err == nil && test.ExpectError {
				t.Errorf("Expected error")
			}
			if !reflect.DeepEqual(result, test.ExpectedResult) {
				for _, entry := range result {
					t.Logf("%+v", entry)
				}
				t.Errorf("Unexpected result")
			}
		})
	}
}
