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

package sort

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
)

type testEmbedded struct {
	EmbeddedInt int `column:"embeddedInt"`
}

type testEmbeddedPtr struct {
	EmbeddedPtrInt int `column:"embeddedPtrInt"`
}

type testData struct {
	testEmbedded
	*testEmbeddedPtr
	Int       int     `column:"int"`
	Uint      uint    `column:"uint"`
	String    string  `column:"string"`
	Float32   float32 `column:"float32"`
	Float64   float64 `column:"float64"`
	Bool      bool    `column:"bool"`
	Group     string  `column:"group"`
	Extractor int     `column:"extractor"`
}

func getTestCol(t *testing.T) *columns.Columns[testData] {
	cols, err := columns.NewColumns[testData]()
	if err != nil {
		t.Errorf("Failed to initialize %v", err)
	}
	cols.MustSetExtractor("extractor", func(t *testData) string {
		return fmt.Sprint(t.Extractor)
	})
	cols.MustAddColumn(columns.Attributes{
		Name: "virtual_column",
	}, func(*testData) string {
		return ""
	})

	return cols
}

func TestSorter(t *testing.T) {
	testEntries := []*testData{
		nil,
		{Int: 1, Uint: 2, String: "c", Float32: 3, Float64: 4, Group: "b", testEmbedded: testEmbedded{EmbeddedInt: 7}, testEmbeddedPtr: &testEmbeddedPtr{EmbeddedPtrInt: 7}, Extractor: 1},
		nil,
		{Int: 2, Uint: 3, String: "d", Float32: 4, Float64: 5, Group: "b", testEmbedded: testEmbedded{EmbeddedInt: 6}, testEmbeddedPtr: &testEmbeddedPtr{EmbeddedPtrInt: 6}, Extractor: 2},
		nil,
		{Int: 3, Uint: 4, String: "e", Float32: 5, Float64: 1, Group: "a", testEmbedded: testEmbedded{EmbeddedInt: 5}, testEmbeddedPtr: nil, Extractor: 3},
		nil,
		{Int: 4, Uint: 5, String: "a", Float32: 1, Float64: 2, Group: "a", testEmbedded: testEmbedded{EmbeddedInt: 4}, testEmbeddedPtr: &testEmbeddedPtr{EmbeddedPtrInt: 4}, Extractor: 4},
		nil,
		{Int: 5, Uint: 1, String: "b", Float32: 2, Float64: 3, Group: "c", testEmbedded: testEmbedded{EmbeddedInt: 3}, testEmbeddedPtr: &testEmbeddedPtr{EmbeddedPtrInt: 3}, Extractor: 5},
		nil,
	}

	// Using shuffle should cover all sorting paths
	rand.Seed(0)

	cmap := getTestCol(t).GetColumnMap()

	shuffle := func() {
		rand.Shuffle(len(testEntries), func(i, j int) { testEntries[i], testEntries[j] = testEntries[j], testEntries[i] })
	}

	if !CanSortBy(cmap, []string{"uint"}) {
		t.Errorf("expected sort to be able to sort by \"uint\" (struct field without custom extractor)")
	}
	if !CanSortBy(cmap, []string{"extractor"}) {
		t.Errorf("expected sort to be able to sort by \"extractor\" (struct field with custom extractor)")
	}
	if CanSortBy(cmap, []string{"virtual_column"}) {
		t.Errorf("expected sort to not be able to sort by \"virtual_column\" (virtual column)")
	}
	if CanSortBy(cmap, []string{"non_existent_column"}) {
		t.Errorf("expected sort to not be able to sort by \"non_existent_column\" (column doesn't exist)")
	}

	shuffle()
	SortEntries(cmap, testEntries, []string{"uint"})
	if testEntries[0].Uint != 1 {
		t.Errorf("expected value to be 1")
	}

	shuffle()
	SortEntries(cmap, testEntries, []string{"-uint"})
	if testEntries[0].Uint != 5 {
		t.Errorf("expected value to be 5")
	}

	shuffle()
	SortEntries(cmap, testEntries, []string{"int"})
	if testEntries[0].Int != 1 {
		t.Errorf("expected value to be 1")
	}

	shuffle()
	SortEntries(cmap, testEntries, []string{"-int"})
	if testEntries[0].Int != 5 {
		t.Errorf("expected value to be 5")
	}

	shuffle()
	SortEntries(cmap, testEntries, []string{"float32"})
	if testEntries[0].Float32 != 1 {
		t.Errorf("expected value to be 1")
	}

	shuffle()
	SortEntries(cmap, testEntries, []string{"-float32"})
	if testEntries[0].Float32 != 5 {
		t.Errorf("expected value to be 5")
	}

	shuffle()
	SortEntries(cmap, testEntries, []string{"float64"})
	if testEntries[0].Float64 != 1 {
		t.Errorf("expected value to be 1")
	}

	shuffle()
	SortEntries(cmap, testEntries, []string{"-float64"})
	if testEntries[0].Float64 != 5 {
		t.Errorf("expected value to be 5")
	}

	shuffle()
	SortEntries(cmap, testEntries, []string{"group", "string"})
	if testEntries[0].Group != "a" || testEntries[0].String != "a" {
		t.Errorf("expected value to be a (group) and a (string)")
	}

	shuffle()
	SortEntries(cmap, testEntries, []string{"-embeddedInt"})
	if testEntries[0].EmbeddedInt != 7 {
		t.Errorf("expected embedded value to be a 7")
	}

	shuffle()
	SortEntries(cmap, testEntries, []string{"-embeddedPtrInt"})
	if testEntries[0].EmbeddedPtrInt != 7 {
		t.Errorf("expected embedded ptr value to be a 7")
	}

	shuffle()
	SortEntries(cmap, testEntries, []string{"-extractor"})
	if testEntries[0].Extractor != 5 {
		t.Errorf("expected value to be 5")
	}

	shuffle()
	SortEntries(cmap, testEntries, []string{"string"})
	if testEntries[0].String != "a" {
		t.Errorf("expected value to be a")
	}

	// Sort by unsupported column - should result in noop
	SortEntries(cmap, testEntries, []string{"bool"})
	if testEntries[0].String != "a" {
		t.Errorf("expected value to be a")
	}

	// Sort by invalid column - should result in noop
	SortEntries(cmap, testEntries, []string{"invalid"})
	if testEntries[0].String != "a" {
		t.Errorf("expected value to be a")
	}

	// Sort by empty column - should result in noop
	SortEntries(cmap, testEntries, []string{""})
	if testEntries[0].String != "a" {
		t.Errorf("expected value to be a")
	}

	// Sort nil array - should result in noop
	SortEntries(cmap, nil, []string{""})
}

func TestCanSortBy(t *testing.T) {
	cmap := getTestCol(t).GetColumnMap()

	if !CanSortBy(cmap, []string{"uint"}) {
		t.Errorf("expected sort to be able to sort by \"uint\" (struct field without custom extractor)")
	}
	if !CanSortBy(cmap, []string{"extractor"}) {
		t.Errorf("expected sort to be able to sort by \"extractor\" (struct field with custom extractor)")
	}
	if CanSortBy(cmap, []string{"virtual_column"}) {
		t.Errorf("expected sort to not be able to sort by \"virtual_column\" (virtual column)")
	}
	if CanSortBy(cmap, []string{"non_existent_column"}) {
		t.Errorf("expected sort to not be able to sort by \"non_existent_column\" (column doesn't exist)")
	}
}

func TestFilterSortableColumns(t *testing.T) {
	cmap := getTestCol(t).GetColumnMap()

	valid, invalid := FilterSortableColumns(cmap, []string{"uint"})
	if !reflect.DeepEqual(valid, []string{"uint"}) || len(invalid) != 0 {
		t.Errorf("expected FilterSortableColumns to return \"uint\" in the valid array (struct field without custom extractor)")
	}
	valid, invalid = FilterSortableColumns(cmap, []string{"extractor"})
	if !reflect.DeepEqual(valid, []string{"extractor"}) || len(invalid) != 0 {
		t.Errorf("expected FilterSortableColumns to return \"extractor\" in the valid array (struct field with custom extractor)")
	}
	valid, invalid = FilterSortableColumns(cmap, []string{"virtual_column"})
	if len(valid) != 0 || !reflect.DeepEqual(invalid, []string{"virtual_column"}) {
		t.Errorf("expected FilterSortableColumns to return \"virtual_column\" in the invalid array (virtual column)")
	}
	valid, invalid = FilterSortableColumns(cmap, []string{"non_existent_column"})
	if len(valid) != 0 || !reflect.DeepEqual(invalid, []string{"non_existent_column"}) {
		t.Errorf("expected FilterSortableColumns to return \"non_existent_column\" in the invalid array (column doesn't exist)")
	}

	valid, _ = FilterSortableColumns(cmap, []string{"uint", "extractor"})
	if len(valid) != 2 || !reflect.DeepEqual(valid, []string{"uint", "extractor"}) {
		t.Errorf("expected FilterSortableColumns to not change the ordering")
	}
}
