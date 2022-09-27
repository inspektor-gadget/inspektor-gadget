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

package textcolumns

import (
	"strings"
	"testing"

	"github.com/kinvolk/inspektor-gadget/pkg/columns"
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

func TestTextColumnsFormatter_FormatEntryAndTable(t *testing.T) {
	expected := []string{
		"Alice        32   1.74     1000 true    ",
		"Bob          26   1.73     -200 true    ",
		"Eve          99   5.12  1000000 false   ",
		"",
	}
	formatter := NewFormatter(testColumns, WithRowDivider(DividerDash))

	t.Run("FormatEntry", func(t *testing.T) {
		for i, entry := range testEntries {
			if res := formatter.FormatEntry(entry); res != expected[i] {
				t.Errorf("got %s, expected %s", res, expected[i])
			}
		}
	})

	t.Run("FormatTable", func(t *testing.T) {
		out := formatter.FormatTable(testEntries)
		if out != strings.Join(append([]string{"NAME        AGE   SIZE  BALANCE CANDANCE", "————————————————————————————————————————"}, expected...), "\n") {
			t.Errorf("got %s", out)
		}
	})
}

func TestTextColumnsFormatter_FormatHeader(t *testing.T) {
	formatter := NewFormatter(testColumns)

	expected := "NAME        AGE   SIZE  BALANCE CANDANCE"
	if res := formatter.FormatHeader(); res != expected {
		t.Errorf("got %s, expected %s", res, expected)
	}

	formatter.options.HeaderStyle = HeaderStyleLowercase
	expected = "name        age   size  balance candance"
	if res := formatter.FormatHeader(); res != expected {
		t.Errorf("got %s, expected %s", res, expected)
	}

	formatter.options.HeaderStyle = HeaderStyleNormal
	expected = "name        age   size  balance canDance"
	if res := formatter.FormatHeader(); res != expected {
		t.Errorf("got %s, expected %s", res, expected)
	}
}

func TestTextColumnsFormatter_FormatRowDivider(t *testing.T) {
	formatter := NewFormatter(testColumns, WithRowDivider(DividerDash))
	expected := "————————————————————————————————————————"
	if res := formatter.FormatRowDivider(); res != expected {
		t.Errorf("got %s, expected %s", res, expected)
	}
}

func TestTextColumnsFormatter_RecalculateWidths(t *testing.T) {
	formatter := NewFormatter(testColumns, WithRowDivider(DividerDash))
	maxWidth := 100
	formatter.RecalculateWidths(maxWidth, true)
	if clen := len([]rune(formatter.FormatHeader())); clen != 100 {
		t.Errorf("expected header to have width of %d, got %d", maxWidth, clen)
	}
	if clen := len([]rune(formatter.FormatRowDivider())); clen != 100 {
		t.Errorf("expected row divider to have width of %d, got %d", maxWidth, clen)
	}
	for _, e := range testEntries {
		if e != nil {
			if clen := len([]rune(formatter.FormatEntry(e))); clen != 100 {
				t.Errorf("expected entry to have width of %d, got %d", maxWidth, clen)
			}
		}
	}
}

func TestTextColumnsFormatter_AdjustWidthsToContent(t *testing.T) {
	/*
		Expected result (32 characters):
		NAME   AGE SIZE BALANCE CANDANCE
		————————————————————————————————
		Alice   32 1.74    1000 true
		Bob     26 1.73    -200 true
		Eve     99 5.12 1000000 false
	*/
	formatter := NewFormatter(testColumns, WithRowDivider(DividerDash))
	formatter.AdjustWidthsToContent(testEntries, true, 0, false)
	if cstr := formatter.FormatHeader(); cstr != "NAME   AGE SIZE BALANCE CANDANCE" {
		t.Errorf("expected header does not match, got %s", cstr)
	}
	if cstr := formatter.FormatRowDivider(); cstr != "————————————————————————————————" {
		t.Errorf("expected row divider does not match, got %s", cstr)
	}
	if cstr := formatter.FormatEntry(testEntries[0]); cstr != "Alice   32 1.74    1000 true    " {
		t.Errorf("expected entry does not match, got %s", cstr)
	}
}

func TestTextColumnsFormatter_AdjustWidthsToContentNoHeaders(t *testing.T) {
	/*
		Expected result (29 characters):
		NAME   AGE SIZE BALANCE CAND…
		—————————————————————————————
		Alice   32 1.74    1000 true
		Bob     26 1.73    -200 true
		Eve     99 5.12 1000000 false
	*/
	formatter := NewFormatter(testColumns, WithRowDivider(DividerDash))
	formatter.AdjustWidthsToContent(testEntries, false, 0, false)
	if cstr := formatter.FormatHeader(); cstr != "NAME   AGE SIZE BALANCE CAND…" {
		t.Errorf("expected header does not match, got %s", cstr)
	}
	if cstr := formatter.FormatRowDivider(); cstr != "—————————————————————————————" {
		t.Errorf("expected row divider does not match, got %s", cstr)
	}
	if cstr := formatter.FormatEntry(testEntries[0]); cstr != "Alice   32 1.74    1000 true " {
		t.Errorf("expected entry does not match, got %s", cstr)
	}
}

func TestTextColumnsFormatter_AdjustWidthsMaxWidth(t *testing.T) {
	/*
		Expected result (9 characters):
		N… …  … …
		—————————
		A… …  … …
		B… …  … …
		E… …  … …
	*/
	formatter := NewFormatter(testColumns, WithRowDivider(DividerDash))
	formatter.AdjustWidthsToContent(testEntries, false, 9, true)
	if cstr := formatter.FormatHeader(); cstr != "N… …  … …" {
		t.Errorf("expected header does not match, got %s", cstr)
	}
	if cstr := formatter.FormatRowDivider(); cstr != "—————————" {
		t.Errorf("expected row divider does not match, got %s", cstr)
	}
	if cstr := formatter.FormatEntry(testEntries[0]); cstr != "A… …  … …" {
		t.Errorf("expected entry does not match, got %s", cstr)
	}
}

func TestWidthRestrictions(t *testing.T) {
	type testStruct struct {
		Name        string `column:"name,width:5,minWidth:2,maxWidth:10"`
		SecondField string `column:"second"`
	}
	entries := []*testStruct{
		{"123456789012", "123456789012"},
		{"234567890123", "234567890123"},
	}
	cols, err := columns.NewColumns[testStruct]()
	if err != nil {
		t.Fatalf("error initializing")
	}
	formatter := NewFormatter(cols.GetColumnMap(), WithRowDivider(DividerDash), WithAutoScale(true))
	t.Run("maxWidth", func(t *testing.T) {
		formatter.RecalculateWidths(40, false)
		if cstr := strings.TrimSpace(formatter.FormatEntry(entries[0])); cstr != "123456789… 123456789012" {
			t.Errorf("expected entry does not match, got %s", cstr)
		}
	})
	t.Run("minWidth", func(t *testing.T) {
		formatter.RecalculateWidths(1, false)
		if cstr := strings.TrimSpace(formatter.FormatEntry(entries[0])); cstr != "1… …" {
			t.Errorf("expected entry does not match, got %s", cstr)
		}
	})
}
