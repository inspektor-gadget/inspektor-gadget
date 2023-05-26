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

package filter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
)

func TestFilters(t *testing.T) {
	type embeddedData struct {
		Int  int `column:"embeddedInt"`
		Uint int `column:"embeddedUint"`
	}
	type testData struct {
		Int              int           `column:"int,align:right,width:6"`
		Int8             int8          `column:"int8,align:right,width:6"`
		Int16            int16         `column:"int16,align:right,width:6"`
		Int32            int32         `column:"int32,align:right,width:6"`
		Int64            int64         `column:"int64,align:right,width:6"`
		Uint             uint          `column:"uint,align:right,width:6"`
		Uint8            uint8         `column:"uint8,align:right,width:6"`
		Uint16           uint16        `column:"uint16,align:right,width:6"`
		Uint32           uint32        `column:"uint32,align:right,width:6"`
		Uint64           uint64        `column:"uint64,align:right,width:6"`
		String           string        `column:"string"`
		Dummy            string        // This a dummy field that we can expose using a virtual field
		Time             int64         `column:"time,align:right,width:24,group:sum"`
		Float32          float32       `column:"float32"`
		Float64          float64       `column:"float64"`
		Unsupported      struct{}      `column:"unsupported"`
		EmbeddedDirect   embeddedData  `column:"embeddedDirectStruct"`
		EmbeddedPtr      *embeddedData `column:"embeddedPtrStruct"`
		EmbeddedEmptyPtr *embeddedData `column:"embeddedEmptyPtrStruct"`
	}

	type filterTest struct {
		filterString  string
		expectedCount int
		expectError   bool
		description   string
	}

	filterEntries := []*testData{
		{
			String:         "",
			Dummy:          "",
			Int:            7,
			Int8:           7,
			Int16:          7,
			Int32:          7,
			Int64:          7,
			Uint:           7,
			Uint8:          7,
			Uint16:         7,
			Uint32:         7,
			Uint64:         7,
			Float32:        7,
			Float64:        7,
			EmbeddedDirect: embeddedData{Int: 7, Uint: 7},
			EmbeddedPtr:    &embeddedData{Int: 7, Uint: 7},
		},
		{
			String:         "Demo 123",
			Dummy:          "Demo 123",
			Int:            1,
			Int8:           1,
			Int16:          1,
			Int32:          1,
			Int64:          1,
			Uint:           1,
			Uint8:          1,
			Uint16:         1,
			Uint32:         1,
			Uint64:         1,
			Float32:        1,
			Float64:        1,
			EmbeddedDirect: embeddedData{Int: 1, Uint: 1},
			EmbeddedPtr:    &embeddedData{Int: 1, Uint: 1},
		},
		{
			String:         "Demo 234",
			Dummy:          "Demo 234",
			Int:            2,
			Int8:           2,
			Int16:          2,
			Int32:          2,
			Int64:          2,
			Uint:           2,
			Uint8:          2,
			Uint16:         2,
			Uint32:         2,
			Uint64:         2,
			Float32:        2,
			Float64:        2,
			EmbeddedDirect: embeddedData{Int: 2, Uint: 2},
			EmbeddedPtr:    &embeddedData{Int: 2, Uint: 2},
		},
		{
			String:         "Demo 234",
			Dummy:          "Demo 234",
			Int:            3,
			Int8:           3,
			Int16:          3,
			Int32:          3,
			Int64:          3,
			Uint:           3,
			Uint8:          3,
			Uint16:         3,
			Uint32:         3,
			Uint64:         3,
			Float32:        3,
			Float64:        3,
			EmbeddedDirect: embeddedData{Int: 3, Uint: 3},
			EmbeddedPtr:    &embeddedData{Int: 3, Uint: 3},
		},
		{
			String:         "Foobar",
			Dummy:          "Foobar",
			Int:            2,
			Int8:           2,
			Int16:          2,
			Int32:          2,
			Int64:          2,
			Uint:           2,
			Uint8:          2,
			Uint16:         2,
			Uint32:         2,
			Uint64:         2,
			Float32:        2,
			Float64:        2,
			EmbeddedDirect: embeddedData{Int: 2, Uint: 2},
			EmbeddedPtr:    &embeddedData{Int: 2, Uint: 2},
		},
		nil,
	}

	filterTests := []filterTest{
		{filterString: "", expectedCount: 0, expectError: true, description: "empty filter, error"},
		{filterString: "string", expectedCount: 1, expectError: false, description: "empty value in column string"},
		{filterString: "string:", expectedCount: 1, expectError: false, description: "same"},
		{filterString: "string:Demo 123", expectedCount: 1, expectError: false, description: "exact match on string"},
		{filterString: "string:>Demo", expectedCount: 4, expectError: false, description: "gt match on string"},
		{filterString: "string:>=Demo", expectedCount: 4, expectError: false, description: "gte match on string"},
		{filterString: "string:<Demo", expectedCount: 1, expectError: false, description: "lt match on string"},
		{filterString: "string:<=Demo", expectedCount: 1, expectError: false, description: "lte match on string"},
		{filterString: "string:demo 123", expectedCount: 0, expectError: false, description: "lowercase, not found"},
		{filterString: "string:~Demo", expectedCount: 3, expectError: false, description: "regular expression search"},
		{filterString: "string:~demo", expectedCount: 0, expectError: false, description: "case-sensitive regular expression search"},
		{filterString: "string:~(?i)demo", expectedCount: 3, expectError: false, description: "case-insensitive regular expression search"},
		{filterString: "string:!~(?i)demo", expectedCount: 2, expectError: false, description: "negated case-insensitive regular expression search"},
		{filterString: "string:~(?i)??//{demo", expectedCount: 0, expectError: true, description: "garbage regular expression search"},

		{filterString: "int:", expectedCount: 0, expectError: true, description: "match on int, empty string"},
		{filterString: "int:1", expectedCount: 1, expectError: false, description: "match on int, exact match"},
		{filterString: "int:~1", expectedCount: 0, expectError: true, description: "match on int, wrong comparison type"},
		{filterString: "int:!1", expectedCount: 4, expectError: false, description: "match on int, negated"},
		{filterString: "int:<2", expectedCount: 1, expectError: false, description: "match on int, lt"},
		{filterString: "int:<=1", expectedCount: 1, expectError: false, description: "match on int, lte"},
		{filterString: "int:>1", expectedCount: 4, expectError: false, description: "match on int, gt"},
		{filterString: "int:>=1", expectedCount: 5, expectError: false, description: "match on int, gte"},
		{filterString: "uint:", expectedCount: 0, expectError: true, description: "match on uint, empty string"},
		{filterString: "uint:1", expectedCount: 1, expectError: false, description: "match on uint, empty string"},
		{filterString: "uint:~1", expectedCount: 0, expectError: true, description: "match on uint, wrong comparison type"},
		{filterString: "uint:!1", expectedCount: 4, expectError: false, description: "match on uint, negated"},
		{filterString: "uint:<2", expectedCount: 1, expectError: false, description: "match on uint, lt"},
		{filterString: "uint:<=1", expectedCount: 1, expectError: false, description: "match on uint, lte"},
		{filterString: "uint:>1", expectedCount: 4, expectError: false, description: "match on uint, gt"},
		{filterString: "uint:>=1", expectedCount: 5, expectError: false, description: "match on uint, gte"},

		{filterString: "int8:", expectedCount: 0, expectError: true, description: "match on int8, empty string"},
		{filterString: "int8:1", expectedCount: 1, expectError: false, description: "match on int8, exact match"},
		{filterString: "int8:~1", expectedCount: 0, expectError: true, description: "match on int8, wrong comparison type"},
		{filterString: "int8:!1", expectedCount: 4, expectError: false, description: "match on int8, negated"},
		{filterString: "int8:<2", expectedCount: 1, expectError: false, description: "match on int8, lt"},
		{filterString: "int8:<=1", expectedCount: 1, expectError: false, description: "match on int8, lte"},
		{filterString: "int8:>1", expectedCount: 4, expectError: false, description: "match on int8, gt"},
		{filterString: "int8:>=1", expectedCount: 5, expectError: false, description: "match on int8, gte"},
		{filterString: "uint8:", expectedCount: 0, expectError: true, description: "match on uint8, empty string"},
		{filterString: "uint8:1", expectedCount: 1, expectError: false, description: "match on uint8, empty string"},
		{filterString: "uint8:~1", expectedCount: 0, expectError: true, description: "match on uint8, wrong comparison type"},
		{filterString: "uint8:!1", expectedCount: 4, expectError: false, description: "match on uint8, negated"},
		{filterString: "uint8:<2", expectedCount: 1, expectError: false, description: "match on uint8, lt"},
		{filterString: "uint8:<=1", expectedCount: 1, expectError: false, description: "match on uint8, lte"},
		{filterString: "uint8:>1", expectedCount: 4, expectError: false, description: "match on uint8, gt"},
		{filterString: "uint8:>=1", expectedCount: 5, expectError: false, description: "match on uint8, gte"},

		{filterString: "int16:", expectedCount: 0, expectError: true, description: "match on int16, empty string"},
		{filterString: "int16:1", expectedCount: 1, expectError: false, description: "match on int16, exact match"},
		{filterString: "int16:~1", expectedCount: 0, expectError: true, description: "match on int16, wrong comparison type"},
		{filterString: "int16:!1", expectedCount: 4, expectError: false, description: "match on int16, negated"},
		{filterString: "int16:<2", expectedCount: 1, expectError: false, description: "match on int16, lt"},
		{filterString: "int16:<=1", expectedCount: 1, expectError: false, description: "match on int16, lte"},
		{filterString: "int16:>1", expectedCount: 4, expectError: false, description: "match on int16, gt"},
		{filterString: "int16:>=1", expectedCount: 5, expectError: false, description: "match on int16, gte"},
		{filterString: "uint16:", expectedCount: 0, expectError: true, description: "match on uint16, empty string"},
		{filterString: "uint16:1", expectedCount: 1, expectError: false, description: "match on uint16, empty string"},
		{filterString: "uint16:~1", expectedCount: 0, expectError: true, description: "match on uint16, wrong comparison type"},
		{filterString: "uint16:!1", expectedCount: 4, expectError: false, description: "match on uint16, negated"},
		{filterString: "uint16:<2", expectedCount: 1, expectError: false, description: "match on uint16, lt"},
		{filterString: "uint16:<=1", expectedCount: 1, expectError: false, description: "match on uint16, lte"},
		{filterString: "uint16:>1", expectedCount: 4, expectError: false, description: "match on uint16, gt"},
		{filterString: "uint16:>=1", expectedCount: 5, expectError: false, description: "match on uint16, gte"},

		{filterString: "int32:", expectedCount: 0, expectError: true, description: "match on int32, empty string"},
		{filterString: "int32:1", expectedCount: 1, expectError: false, description: "match on int32, exact match"},
		{filterString: "int32:~1", expectedCount: 0, expectError: true, description: "match on int32, wrong comparison type"},
		{filterString: "int32:!1", expectedCount: 4, expectError: false, description: "match on int32, negated"},
		{filterString: "int32:<2", expectedCount: 1, expectError: false, description: "match on int32, lt"},
		{filterString: "int32:<=1", expectedCount: 1, expectError: false, description: "match on int32, lte"},
		{filterString: "int32:>1", expectedCount: 4, expectError: false, description: "match on int32, gt"},
		{filterString: "int32:>=1", expectedCount: 5, expectError: false, description: "match on int32, gte"},
		{filterString: "uint32:", expectedCount: 0, expectError: true, description: "match on uint32, empty string"},
		{filterString: "uint32:1", expectedCount: 1, expectError: false, description: "match on uint32, empty string"},
		{filterString: "uint32:~1", expectedCount: 0, expectError: true, description: "match on uint32, wrong comparison type"},
		{filterString: "uint32:!1", expectedCount: 4, expectError: false, description: "match on uint32, negated"},
		{filterString: "uint32:<2", expectedCount: 1, expectError: false, description: "match on uint32, lt"},
		{filterString: "uint32:<=1", expectedCount: 1, expectError: false, description: "match on uint32, lte"},
		{filterString: "uint32:>1", expectedCount: 4, expectError: false, description: "match on uint32, gt"},
		{filterString: "uint32:>=1", expectedCount: 5, expectError: false, description: "match on uint32, gte"},

		{filterString: "int64:", expectedCount: 0, expectError: true, description: "match on int64, empty string"},
		{filterString: "int64:1", expectedCount: 1, expectError: false, description: "match on int64, exact match"},
		{filterString: "int64:~1", expectedCount: 0, expectError: true, description: "match on int64, wrong comparison type"},
		{filterString: "int64:!1", expectedCount: 4, expectError: false, description: "match on int64, negated"},
		{filterString: "int64:<2", expectedCount: 1, expectError: false, description: "match on int64, lt"},
		{filterString: "int64:<=1", expectedCount: 1, expectError: false, description: "match on int64, lte"},
		{filterString: "int64:>1", expectedCount: 4, expectError: false, description: "match on int64, gt"},
		{filterString: "int64:>=1", expectedCount: 5, expectError: false, description: "match on int64, gte"},
		{filterString: "uint64:", expectedCount: 0, expectError: true, description: "match on uint64, empty string"},
		{filterString: "uint64:1", expectedCount: 1, expectError: false, description: "match on uint64, empty string"},
		{filterString: "uint64:~1", expectedCount: 0, expectError: true, description: "match on uint64, wrong comparison type"},
		{filterString: "uint64:!1", expectedCount: 4, expectError: false, description: "match on uint64, negated"},
		{filterString: "uint64:<2", expectedCount: 1, expectError: false, description: "match on uint64, lt"},
		{filterString: "uint64:<=1", expectedCount: 1, expectError: false, description: "match on uint64, lte"},
		{filterString: "uint64:>1", expectedCount: 4, expectError: false, description: "match on uint64, gt"},
		{filterString: "uint64:>=1", expectedCount: 5, expectError: false, description: "match on uint64, gte"},

		{filterString: "float32:", expectedCount: 0, expectError: true, description: "match on float32, empty string"},
		{filterString: "float32:1", expectedCount: 1, expectError: false, description: "match on float32, exact match"},
		{filterString: "float32:~1", expectedCount: 0, expectError: true, description: "match on float32, wrong comparison type"},
		{filterString: "float32:!1", expectedCount: 4, expectError: false, description: "match on float32, negated"},
		{filterString: "float32:<2", expectedCount: 1, expectError: false, description: "match on float32, lt"},
		{filterString: "float32:<=1", expectedCount: 1, expectError: false, description: "match on float32, lte"},
		{filterString: "float32:>1", expectedCount: 4, expectError: false, description: "match on float32, gt"},
		{filterString: "float32:>=1", expectedCount: 5, expectError: false, description: "match on float32, gte"},
		{filterString: "float64:", expectedCount: 0, expectError: true, description: "match on float64, empty string"},
		{filterString: "float64:1", expectedCount: 1, expectError: false, description: "match on float64, empty string"},
		{filterString: "float64:~1", expectedCount: 0, expectError: true, description: "match on float64, wrong comparison type"},
		{filterString: "float64:!1", expectedCount: 4, expectError: false, description: "match on float64, negated"},
		{filterString: "float64:<2", expectedCount: 1, expectError: false, description: "match on float64, lt"},
		{filterString: "float64:<=1", expectedCount: 1, expectError: false, description: "match on float64, lte"},
		{filterString: "float64:>1", expectedCount: 4, expectError: false, description: "match on float64, gt"},
		{filterString: "float64:>=1", expectedCount: 5, expectError: false, description: "match on float64, gte"},

		{filterString: "embeddedDirectStruct.embeddedInt:", expectedCount: 0, expectError: true, description: "match on embedded int, empty string"},
		{filterString: "embeddedDirectStruct.embeddedInt:1", expectedCount: 1, expectError: false, description: "match on embedded int, exact match"},
		{filterString: "embeddedDirectStruct.embeddedInt:~1", expectedCount: 0, expectError: true, description: "match on embedded int, wrong comparison type"},
		{filterString: "embeddedDirectStruct.embeddedInt:!1", expectedCount: 4, expectError: false, description: "match on embedded int, negated"},
		{filterString: "embeddedDirectStruct.embeddedInt:<2", expectedCount: 1, expectError: false, description: "match on embedded int, lt"},
		{filterString: "embeddedDirectStruct.embeddedInt:<=1", expectedCount: 1, expectError: false, description: "match on embedded int, lte"},
		{filterString: "embeddedDirectStruct.embeddedInt:>1", expectedCount: 4, expectError: false, description: "match on embedded int, gt"},
		{filterString: "embeddedDirectStruct.embeddedInt:>=1", expectedCount: 5, expectError: false, description: "match on embedded int, gte"},

		{filterString: "embeddedPtrStruct.embeddedInt:", expectedCount: 0, expectError: true, description: "match on embedded int (using ptr), empty string"},
		{filterString: "embeddedPtrStruct.embeddedInt:1", expectedCount: 1, expectError: false, description: "match on embedded int (using ptr), exact match"},
		{filterString: "embeddedPtrStruct.embeddedInt:~1", expectedCount: 0, expectError: true, description: "match on embedded int (using ptr), wrong comparison type"},
		{filterString: "embeddedPtrStruct.embeddedInt:!1", expectedCount: 4, expectError: false, description: "match on embedded int (using ptr), negated"},
		{filterString: "embeddedPtrStruct.embeddedInt:<2", expectedCount: 1, expectError: false, description: "match on embedded int (using ptr), lt"},
		{filterString: "embeddedPtrStruct.embeddedInt:<=1", expectedCount: 1, expectError: false, description: "match on embedded int (using ptr), lte"},
		{filterString: "embeddedPtrStruct.embeddedInt:>1", expectedCount: 4, expectError: false, description: "match on embedded int (using ptr), gt"},
		{filterString: "embeddedPtrStruct.embeddedInt:>=1", expectedCount: 5, expectError: false, description: "match on embedded int (using ptr), gte"},

		{filterString: "embeddedDirectStruct.embeddedUint:1", expectedCount: 1, expectError: false, description: "match on uint with second embedded field, exact match"},
		{filterString: "embeddedPtrStruct.embeddedUint:1", expectedCount: 1, expectError: false, description: "match on uint with second embedded field (using ptr), exact match"},

		{filterString: "embeddedEmptyPtrStruct.embeddedInt:0", expectedCount: 5, expectError: false, description: "match on embedded int in nil pointer, exact match (testing defaults)"},

		{filterString: "unsupported:1", expectedCount: 0, expectError: true, description: "unsupported field"},

		{filterString: "virtual:Demo 123", expectedCount: 1, expectError: false, description: "exact match on virtual column"},
	}

	cols, err := columns.NewColumns[testData]()
	require.NoError(t, err)

	cols.MustAddColumn(columns.Attributes{Name: "virtual"}, func(t *testData) string {
		return t.Dummy
	})

	cmap := cols.GetColumnMap()

	t.Run("test empty input", func(t *testing.T) {
		res, err := FilterEntries(cmap, nil, []string{""})
		assert.NoError(t, err)
		assert.Nil(t, res)
	})

	for _, filterTest := range filterTests {
		t.Run(filterTest.description, func(t *testing.T) {
			out, err := FilterEntries(cmap, filterEntries, []string{filterTest.filterString})
			assert.False(t, err != nil && !filterTest.expectError)
			assert.False(t, err == nil && filterTest.expectError)
			assert.Len(t, out, filterTest.expectedCount)
		})
	}

	filter, err := GetFilterFromString(cmap, "int8:1")
	require.NoError(t, err)
	assert.False(t, filter.Match(nil), "matching nil on non-negated filter should return false")

	t.Run("multiple filters", func(t *testing.T) {
		out, err := FilterEntries(cmap, filterEntries, []string{"int:1", "int8:1", "string:Demo 123"})
		require.NoError(t, err)
		require.Len(t, out, 1)
		assert.Equal(t, out[0].Int, 1)
	})
}
