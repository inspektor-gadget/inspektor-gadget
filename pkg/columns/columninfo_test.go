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

package columns

import (
	"testing"

	"github.com/kinvolk/inspektor-gadget/pkg/columns/ellipsis"
)

func TestColumnsInvalid(t *testing.T) {
	type testFail1 struct {
		Unknown string `column:"left,unknown"` // unknown parameter
	}
	type testFail2 struct {
		Unknown1 string `column:"unknown"`
		Unknown2 string `column:"unknown"` // double name
	}
	type testFail3 struct {
		testFail2
	}
	_, err := NewColumns[testFail1]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail2]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail3]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
}

func TestColumnsAlign(t *testing.T) {
	type testSuccess1 struct {
		AlignLeft  string `column:"left,align:left"`
		AlignRight string `column:"right,align:right"`
	}
	type testFail1 struct {
		Field string `column:"fail,align"`
	}
	type testFail2 struct {
		Field string `column:"fail,align:"`
	}
	type testFail3 struct {
		Field string `column:"fail,align:foo"`
	}
	type testFail4 struct {
		Field string `column:"fail,align:left:bar"`
	}

	cols, err := NewColumns[testSuccess1]()
	if err != nil {
		t.Fatalf("failed to initialize: %v", err)
	}

	columnName := "left"
	col, ok := cols.GetColumn(columnName)
	if !ok {
		t.Fatalf("expected column %q to exist", columnName)
	}
	if col.Alignment != AlignLeft {
		t.Errorf("expected alignment for column %q to be %q", columnName, "AlignLeft")
	}

	columnName = "right"
	col, ok = cols.GetColumn(columnName)
	if !ok {
		t.Fatalf("expected column %q to exist", columnName)
	}
	if col.Alignment != AlignRight {
		t.Errorf("expected alignment for column %q to be %q", columnName, "AlignRight")
	}

	_, err = NewColumns[testFail1]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail2]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail3]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail4]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
}

func TestColumnsEllipsis(t *testing.T) {
	type testSuccess1 struct {
		EllipsisEmpty      string `column:"empty,ellipsis"`
		EllipsisEmptyColon string `column:"emptyColon,ellipsis:"`
		EllipsisNone       string `column:"none,ellipsis:none"`
		EllipsisStart      string `column:"start,ellipsis:start"`
		EllipsisEnd        string `column:"end,ellipsis:end"`
		EllipsisMiddle     string `column:"middle,ellipsis:middle"`
	}
	type testFail1 struct {
		Field string `column:"fail,ellipsis:foo"`
	}
	type testFail2 struct {
		Field string `column:"fail,ellipsis:left:bar"`
	}

	type check struct {
		Name  string
		Value ellipsis.EllipsisType
	}

	cols, err := NewColumns[testSuccess1]()
	if err != nil {
		t.Fatalf("failed to initialize: %v", err)
	}

	checks := []check{
		{"empty", cols.options.DefaultEllipsis},
		{"emptyColon", cols.options.DefaultEllipsis},
		{"none", ellipsis.None},
		{"start", ellipsis.Start},
		{"end", ellipsis.End},
		{"middle", ellipsis.Middle},
	}

	checkEllipsis := func(chk check) {
		t.Run(chk.Name, func(t *testing.T) {
			col, ok := cols.GetColumn(chk.Name)
			if !ok {
				t.Fatalf("expected column %q to exist", chk.Name)
			}
			if col.EllipsisType != chk.Value {
				t.Errorf("expected ellipsis for column %q to be %q, got %q", chk.Name, chk.Value.String(), col.EllipsisType.String())
			}
		})
	}
	for _, chk := range checks {
		checkEllipsis(chk)
	}

	_, err = NewColumns[testFail1]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail2]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
}

func TestColumnsFixed(t *testing.T) {
	type testSuccess1 struct {
		Field string `column:"field,fixed"`
	}
	type testFail1 struct {
		Field string `column:"fail,fixed:foo"` // with param
	}

	cols, err := NewColumns[testSuccess1]()
	if err != nil {
		t.Fatalf("failed to initialize: %v", err)
	}
	col, ok := cols.GetColumn("field")
	if !ok {
		t.Fatalf("expected column %q to exist", "field")
	}
	if !col.FixedWidth {
		t.Fatalf("expected column %q to have FixedWidth set", "field")
	}

	_, err = NewColumns[testFail1]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
}

func TestColumnsGroup(t *testing.T) {
	type testSuccess1 struct {
		FieldInt     int64   `column:"int,group:sum"`
		FieldUint    int64   `column:"uint,group:sum"`
		FieldFloat32 float32 `column:"float32,group:sum"`
		FieldFloat64 float64 `column:"float64,group:sum"`
	}
	type testFail1 struct {
		Field int64 `column:"fail,group"` // no param
	}
	type testFail2 struct {
		Field int64 `column:"fail,group:"` // empty param
	}
	type testFail3 struct {
		Field int64 `column:"fail,group:foo"` // invalid param
	}
	type testFail4 struct {
		Field int64 `column:"fail,group:sum:bar"` // double param
	}
	type testFail5 struct {
		Field string `column:"fail,group:sum"` // wrong type
	}

	cols, err := NewColumns[testSuccess1]()
	if err != nil {
		t.Fatalf("failed to initialize: %v", err)
	}
	if col, ok := cols.GetColumn("int"); !ok || col.GroupType != GroupTypeSum {
		t.Errorf("expected column %q to have GroupType %q", "int", "GroupTypeSum")
	}
	if col, ok := cols.GetColumn("uint"); !ok || col.GroupType != GroupTypeSum {
		t.Errorf("expected column %q to have GroupType %q", "uint", "GroupTypeSum")
	}
	if col, ok := cols.GetColumn("float32"); !ok || col.GroupType != GroupTypeSum {
		t.Errorf("expected column %q to have GroupType %q", "float32", "GroupTypeSum")
	}
	if col, ok := cols.GetColumn("float64"); !ok || col.GroupType != GroupTypeSum {
		t.Errorf("expected column %q to have GroupType %q", "float64", "GroupTypeSum")
	}

	_, err = NewColumns[testFail1]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail2]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail3]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail4]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail5]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
}

func TestColumnsHide(t *testing.T) {
	type testSuccess1 struct {
		Field string `column:"field,hide"`
	}
	type testFail1 struct {
		Field string `column:"fail,hide:foo"` // with param
	}

	cols, err := NewColumns[testSuccess1]()
	if err != nil {
		t.Fatalf("failed to initialize: %v", err)
	}
	col, ok := cols.GetColumn("field")
	if !ok {
		t.Fatalf("expected column %q to exist", "field")
	}
	if col.Visible {
		t.Fatalf("expected column %q to have Hide set", "field")
	}

	_, err = NewColumns[testFail1]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
}

func TestColumnsOrder(t *testing.T) {
	type testSuccess1 struct {
		FieldWidth int64 `column:"int,order:4"`
	}
	type testFail1 struct {
		Field int64 `column:"fail,order"` // no param
	}
	type testFail2 struct {
		Field int64 `column:"fail,order:"` // empty param
	}
	type testFail3 struct {
		Field int64 `column:"fail,order:foo"` // invalid param
	}
	type testFail4 struct {
		Field int64 `column:"fail,order:sum:bar"` // double param
	}

	cols, err := NewColumns[testSuccess1]()
	if err != nil {
		t.Fatalf("failed to initialize: %v", err)
	}
	if col, ok := cols.GetColumn("int"); !ok || col.Order != 4 {
		t.Errorf("expected column %q to have Order set to %d", "int", 4)
	}

	_, err = NewColumns[testFail1]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail2]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail3]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail4]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
}

func TestColumnsPrecision(t *testing.T) {
	type testSuccess1 struct {
		Float32 float32 `column:"float32,precision:4"`
		Float64 float64 `column:"float64,precision:4"`
	}
	type testFail1 struct {
		Field1 float32 `column:"fail,precision"`
	}
	type testFail2 struct {
		Field float32 `column:"fail,precision:"`
	}
	type testFail3 struct {
		Field float32 `column:"fail,precision:foo"`
	}
	type testFail4 struct {
		Field float32 `column:"fail,precision:-2"`
	}
	type testFail5 struct {
		Field1 float64 `column:"fail,precision"`
	}
	type testFail6 struct {
		Field float64 `column:"fail,precision:"`
	}
	type testFail7 struct {
		Field float64 `column:"fail,precision:foo"`
	}
	type testFail8 struct {
		Field float64 `column:"fail,precision:-2"`
	}
	type testFail9 struct {
		Field string `column:"fail,precision:2"`
	}

	cols, err := NewColumns[testSuccess1]()
	if err != nil {
		t.Fatalf("failed to initialize: %v", err)
	}
	if col, ok := cols.GetColumn("float32"); !ok || col.Precision != 4 {
		t.Errorf("expected column %q to have Precision set to %d", "float32", 4)
	}
	if col, ok := cols.GetColumn("float64"); !ok || col.Precision != 4 {
		t.Errorf("expected column %q to have Precision set to %d", "float64", 4)
	}

	_, err = NewColumns[testFail1]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail2]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail3]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail4]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail5]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail6]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail7]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail8]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail9]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
}

func TestColumnsWidth(t *testing.T) {
	type testSuccess1 struct {
		FieldWidth int64 `column:"int,width:4"`
	}
	type testFail1 struct {
		Field int64 `column:"fail,width"` // no param
	}
	type testFail2 struct {
		Field int64 `column:"fail,width:"` // empty param
	}
	type testFail3 struct {
		Field int64 `column:"fail,width:foo"` // invalid param
	}
	type testFail4 struct {
		Field int64 `column:"fail,width:sum:bar"` // double param
	}

	cols, err := NewColumns[testSuccess1]()
	if err != nil {
		t.Fatalf("failed to initialize: %v", err)
	}
	if col, ok := cols.GetColumn("int"); !ok || col.Width != 4 {
		t.Errorf("expected column %q to have Width set to %d", "int", 4)
	}

	_, err = NewColumns[testFail1]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail2]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail3]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail4]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
}

func TestWithoutColumnTag(t *testing.T) {
	type Main struct {
		StringField string
		IntField    int
	}
	cols, err := NewColumns[Main](WithRequireColumnDefinition(false))
	if err != nil {
		t.Errorf("failed to initialize: %v", err)
	}

	if _, ok := cols.GetColumn("StringField"); !ok {
		t.Errorf("expected a StringField column")
	}
}

func TestColumnFilters(t *testing.T) {
	type Embedded struct {
		EmbeddedString string `column:"embeddedString" columnTags:"test"`
	}
	type Main struct {
		Embedded
		MainString string `column:"mainString" columnTags:"test2"`
	}
	cols, err := NewColumns[Main](WithRequireColumnDefinition(false))
	if err != nil {
		t.Errorf("failed to initialize: %v", err)
	}

	colMap := cols.GetColumnMap(Or(WithEmbedded(true), WithTag("test")))
	if _, ok := colMap.GetColumn("embeddedString"); !ok {
		t.Errorf("expected an embeddedString column after applying filters")
	}

	colMap = cols.GetColumnMap(Or(WithEmbedded(false), WithoutTag("test")))
	if _, ok := colMap.GetColumn("mainString"); !ok {
		t.Errorf("expected a mainString column after applying filters")
	}

	orderedColumns := cols.GetOrderedColumns(And(WithTags([]string{"test2"}), WithoutTags([]string{"test"})))
	if len(orderedColumns) != 1 || orderedColumns[0].Name != "mainString" {
		t.Errorf("expected a mainString column after getting ordered columns using filters")
	}

	orderedColumns = cols.GetOrderedColumns(WithoutTags([]string{"test"})) // missing path
	if len(orderedColumns) != 1 || orderedColumns[0].Name != "mainString" {
		t.Errorf("expected a mainString column after getting ordered columns using filters")
	}
}

func TestColumnMatcher(t *testing.T) {
	type Embedded struct {
		EmbeddedString string `column:"embeddedString" columnTags:"test"`
	}
	type Main struct {
		Embedded
		MainString string `column:"mainString" columnTags:"test2"`
	}

	cols, err := NewColumns[Main]()
	if err != nil {
		t.Errorf("failed to initialize: %v", err)
	}

	c, ok := cols.GetColumn("embeddedString")
	if !ok {
		t.Errorf("expected there to be an embeddedString column")
	}
	if !c.IsEmbedded() {
		t.Errorf("expected the embedded field to be identified as embedded")
	}
	if !c.HasTag("test") {
		t.Errorf("expected the embedded field to have tag 'test'")
	}
	if c.HasTag("test2") {
		t.Errorf("didn't expect the embedded field to have tag 'test2'")
	}

	c, ok = cols.GetColumn("mainString")
	if !ok {
		t.Errorf("expected there to be a mainString column")
	}
	if c.IsEmbedded() {
		t.Errorf("expected mainString to not be identified as embedded")
	}
	if !c.HasTag("test2") {
		t.Errorf("expected mainString to have tag 'test2'")
	}
	if c.HasTag("test") {
		t.Errorf("didn't expect mainString to have tag 'test'")
	}
}
