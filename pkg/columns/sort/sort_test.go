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
	"testing"

	"github.com/stretchr/testify/require"

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
	require.NoError(t, err, "Failed to initialize")
	cols.MustSetExtractor("extractor", func(t *testData) any {
		return fmt.Sprint(t.Extractor)
	})
	cols.MustAddColumn(columns.Attributes{
		Name: "virtual_column",
	}, func(*testData) any {
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
	r := rand.New(rand.NewSource(0))

	cmap := getTestCol(t).GetColumnMap()

	shuffle := func() {
		r.Shuffle(len(testEntries), func(i, j int) { testEntries[i], testEntries[j] = testEntries[j], testEntries[i] })
	}

	require.True(t, CanSortBy(cmap, []string{"uint"}), "expected sort to be able to sort by \"uint\" (struct field without custom extractor)")
	require.True(t, CanSortBy(cmap, []string{"extractor"}), "expected sort to be able to sort by \"extractor\" (struct field with custom extractor)")
	require.False(t, CanSortBy(cmap, []string{"virtual_column"}), "expected sort to not be able to sort by \"virtual_column\" (virtual column)")
	require.False(t, CanSortBy(cmap, []string{"non_existent_column"}), "expected sort to not be able to sort by \"non_existent_column\" (column doesn't exist)")

	shuffle()
	SortEntries(cmap, testEntries, []string{"uint"})
	require.Equal(t, uint(1), testEntries[0].Uint)

	shuffle()
	SortEntries(cmap, testEntries, []string{"-uint"})
	require.Equal(t, uint(5), testEntries[0].Uint)

	shuffle()
	SortEntries(cmap, testEntries, []string{"int"})
	require.Equal(t, 1, testEntries[0].Int)

	shuffle()
	SortEntries(cmap, testEntries, []string{"-int"})
	require.Equal(t, 5, testEntries[0].Int)

	shuffle()
	SortEntries(cmap, testEntries, []string{"float32"})
	require.Equal(t, float32(1), testEntries[0].Float32)

	shuffle()
	SortEntries(cmap, testEntries, []string{"-float32"})
	require.Equal(t, float32(5), testEntries[0].Float32)

	shuffle()
	SortEntries(cmap, testEntries, []string{"float64"})
	require.Equal(t, float64(1), testEntries[0].Float64)

	shuffle()
	SortEntries(cmap, testEntries, []string{"-float64"})
	require.Equal(t, float64(5), testEntries[0].Float64)

	shuffle()
	SortEntries(cmap, testEntries, []string{"group", "string"})
	require.Equal(t, "a", testEntries[0].Group)
	require.Equal(t, "a", testEntries[0].String)

	shuffle()
	SortEntries(cmap, testEntries, []string{"-embeddedInt"})
	require.Equal(t, 7, testEntries[0].EmbeddedInt)

	shuffle()
	SortEntries(cmap, testEntries, []string{"-embeddedPtrInt"})
	require.Equal(t, 7, testEntries[0].EmbeddedPtrInt)

	shuffle()
	SortEntries(cmap, testEntries, []string{"-extractor"})
	require.Equal(t, 5, testEntries[0].Extractor)

	shuffle()
	SortEntries(cmap, testEntries, []string{"string"})
	require.Equal(t, "a", testEntries[0].String)

	// Sort by unsupported column - should result in noop
	SortEntries(cmap, testEntries, []string{"bool"})
	require.Equal(t, "a", testEntries[0].String)

	// Sort by invalid column - should result in noop
	SortEntries(cmap, testEntries, []string{"invalid"})
	require.Equal(t, "a", testEntries[0].String)

	// Sort by empty column - should result in noop
	SortEntries(cmap, testEntries, []string{""})
	require.Equal(t, "a", testEntries[0].String)

	// Sort nil array - should result in noop
	SortEntries(cmap, nil, []string{""})
}

func TestCanSortBy(t *testing.T) {
	cmap := getTestCol(t).GetColumnMap()

	require.True(t, CanSortBy(cmap, []string{"uint"}), "expected sort to be able to sort by \"uint\" (struct field without custom extractor)")
	require.True(t, CanSortBy(cmap, []string{"extractor"}), "expected sort to be able to sort by \"extractor\" (struct field with custom extractor)")
	require.False(t, CanSortBy(cmap, []string{"virtual_column"}), "expected sort to not be able to sort by \"virtual_column\" (virtual column)")
	require.False(t, CanSortBy(cmap, []string{"non_existent_column"}), "expected sort to not be able to sort by \"non_existent_column\" (column doesn't exist)")
}

func TestFilterSortableColumns(t *testing.T) {
	cmap := getTestCol(t).GetColumnMap()

	valid, invalid := FilterSortableColumns(cmap, []string{"uint"})
	require.Equal(t, []string{"uint"}, valid)
	require.Empty(t, invalid)

	valid, invalid = FilterSortableColumns(cmap, []string{"extractor"})
	require.Equal(t, []string{"extractor"}, valid)
	require.Empty(t, invalid)

	valid, invalid = FilterSortableColumns(cmap, []string{"virtual_column"})
	require.Empty(t, valid)
	require.Equal(t, []string{"virtual_column"}, invalid)

	valid, invalid = FilterSortableColumns(cmap, []string{"non_existent_column"})
	require.Empty(t, valid)
	require.Equal(t, []string{"non_existent_column"}, invalid)

	valid, _ = FilterSortableColumns(cmap, []string{"uint", "extractor"})
	require.Len(t, valid, 2)
	require.Equal(t, []string{"uint", "extractor"}, valid)
}
