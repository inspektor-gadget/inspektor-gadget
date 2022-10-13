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
	"reflect"
	"testing"

	"github.com/kinvolk/inspektor-gadget/pkg/columns/ellipsis"
)

func expectColumnsSuccess[T any](t *testing.T, options ...Option) *Columns[T] {
	cols, err := NewColumns[T](options...)
	if err != nil {
		t.Fatalf("Failed to initialize: %v", err)
	}
	return cols
}

func expectColumnsFail[T any](t *testing.T, name string, options ...Option) {
	t.Run(name, func(t *testing.T) {
		_, err := NewColumns[T](options...)
		if err == nil {
			t.Errorf("Succeeded to initialize but expected error")
		}
	})
}

func expectColumn[T any](t *testing.T, cols *Columns[T], columnName string) *Column[T] {
	col, ok := cols.GetColumn(columnName)
	if !ok {
		t.Fatalf("Expected column with name %q", columnName)
	}
	return col
}

func expectColumnValue[T any](t *testing.T, col *Column[T], fieldName string, expectedValue interface{}) {
	columnValue := reflect.ValueOf(col).Elem()
	fieldValue := columnValue.FieldByName(fieldName)
	if !fieldValue.IsValid() {
		t.Errorf("Expected field %q", fieldName)
		return
	}
	if fieldValue.Interface() != expectedValue {
		t.Errorf("Expected field %q to equal %+v, got %+v", fieldName, expectedValue, fieldValue.Interface())
	}
}

func TestColumnsInvalid(t *testing.T) {
	type testFail1 struct {
		Unknown string `column:"left,unknown"`
	}
	type testFail2 struct {
		Unknown1 string `column:"unknown"`
		Unknown2 string `column:"unknown"`
	}
	type testFail3 struct {
		testFail2
	}
	expectColumnsFail[testFail1](t, "unknown parameter")
	expectColumnsFail[testFail2](t, "double name")
	expectColumnsFail[testFail3](t, "nested double name")
}

func TestColumnsAlign(t *testing.T) {
	type testSuccess1 struct {
		AlignLeft  string `column:"left,align:left"`
		AlignRight string `column:"right,align:right"`
	}

	cols := expectColumnsSuccess[testSuccess1](t)
	expectColumnValue(t, expectColumn(t, cols, "left"), "Alignment", AlignLeft)
	expectColumnValue(t, expectColumn(t, cols, "right"), "Alignment", AlignRight)

	expectColumnsFail[struct {
		Field string `column:"fail,align"`
	}](t, "missing parameter")
	expectColumnsFail[struct {
		Field string `column:"fail,align:"`
	}](t, "empty parameter")
	expectColumnsFail[struct {
		Field string `column:"fail,align:foo"`
	}](t, "invalid parameter")
	expectColumnsFail[struct {
		Field string `column:"fail,align:left:bar"`
	}](t, "double parameter")
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

	cols := expectColumnsSuccess[testSuccess1](t)
	expectColumnValue(t, expectColumn(t, cols, "empty"), "EllipsisType", cols.options.DefaultEllipsis)
	expectColumnValue(t, expectColumn(t, cols, "emptyColon"), "EllipsisType", cols.options.DefaultEllipsis)
	expectColumnValue(t, expectColumn(t, cols, "none"), "EllipsisType", ellipsis.None)
	expectColumnValue(t, expectColumn(t, cols, "start"), "EllipsisType", ellipsis.Start)
	expectColumnValue(t, expectColumn(t, cols, "end"), "EllipsisType", ellipsis.End)
	expectColumnValue(t, expectColumn(t, cols, "middle"), "EllipsisType", ellipsis.Middle)

	expectColumnsFail[struct {
		Field string `column:"fail,ellipsis:foo"`
	}](t, "invalid parameter")
	expectColumnsFail[struct {
		Field string `column:"fail,ellipsis:left:bar"`
	}](t, "double parameter")
}

func TestColumnsFixed(t *testing.T) {
	type testSuccess1 struct {
		Field string `column:"field,fixed"`
	}

	cols := expectColumnsSuccess[testSuccess1](t)
	expectColumnValue(t, expectColumn(t, cols, "field"), "FixedWidth", true)

	expectColumnsFail[struct {
		Field string `column:"fail,fixed:foo"`
	}](t, "invalid parameter")
}

func TestColumnsGroup(t *testing.T) {
	type testSuccess1 struct {
		FieldInt     int64   `column:"int,group:sum"`
		FieldUint    int64   `column:"uint,group:sum"`
		FieldFloat32 float32 `column:"float32,group:sum"`
		FieldFloat64 float64 `column:"float64,group:sum"`
	}

	cols := expectColumnsSuccess[testSuccess1](t)
	expectColumnValue(t, expectColumn(t, cols, "int"), "GroupType", GroupTypeSum)
	expectColumnValue(t, expectColumn(t, cols, "uint"), "GroupType", GroupTypeSum)
	expectColumnValue(t, expectColumn(t, cols, "float32"), "GroupType", GroupTypeSum)
	expectColumnValue(t, expectColumn(t, cols, "float64"), "GroupType", GroupTypeSum)

	expectColumnsFail[struct {
		Field int64 `column:"fail,group"`
	}](t, "missing parameter")
	expectColumnsFail[struct {
		Field int64 `column:"fail,group:"`
	}](t, "empty parameter")
	expectColumnsFail[struct {
		Field int64 `column:"fail,group:foo"`
	}](t, "invalid parameter")
	expectColumnsFail[struct {
		Field int64 `column:"fail,group:sum:bar"`
	}](t, "double parameter")
	expectColumnsFail[struct {
		Field string `column:"fail,group:sum"`
	}](t, "wrong type")
}

func TestColumnsHide(t *testing.T) {
	type testSuccess1 struct {
		Field string `column:"field,hide"`
	}

	cols := expectColumnsSuccess[testSuccess1](t)
	expectColumnValue(t, expectColumn(t, cols, "field"), "Visible", false)

	expectColumnsFail[struct {
		Field string `column:"fail,hide:foo"`
	}](t, "invalid parameter")
}

func TestColumnsOrder(t *testing.T) {
	type testSuccess1 struct {
		FieldWidth int64 `column:"int,order:4"`
	}

	cols := expectColumnsSuccess[testSuccess1](t)
	expectColumnValue(t, expectColumn(t, cols, "int"), "Order", 4)

	expectColumnsFail[struct {
		Field int64 `column:"fail,order"`
	}](t, "missing parameter")
	expectColumnsFail[struct {
		Field int64 `column:"fail,order:"`
	}](t, "empty parameter")
	expectColumnsFail[struct {
		Field int64 `column:"fail,order:foo"`
	}](t, "invalid parameter")
	expectColumnsFail[struct {
		Field int64 `column:"fail,order:sum:bar"`
	}](t, "double parameter")
}

func TestColumnsPrecision(t *testing.T) {
	type testSuccess1 struct {
		Float32 float32 `column:"float32,precision:4"`
		Float64 float64 `column:"float64,precision:4"`
	}

	cols := expectColumnsSuccess[testSuccess1](t)
	expectColumnValue(t, expectColumn(t, cols, "float32"), "Precision", 4)
	expectColumnValue(t, expectColumn(t, cols, "float64"), "Precision", 4)

	expectColumnsFail[struct {
		Field1 float32 `column:"fail,precision"`
	}](t, "float32: missing parameter")
	expectColumnsFail[struct {
		Field float32 `column:"fail,precision:"`
	}](t, "float32: empty parameter")
	expectColumnsFail[struct {
		Field float32 `column:"fail,precision:foo"`
	}](t, "float32: invalid parameter")
	expectColumnsFail[struct {
		Field float32 `column:"fail,precision:-2"`
	}](t, "float32: double parameter")
	expectColumnsFail[struct {
		Field1 float64 `column:"fail,precision"`
	}](t, "float64: missing parameter")
	expectColumnsFail[struct {
		Field float64 `column:"fail,precision:"`
	}](t, "float64: empty parameter")
	expectColumnsFail[struct {
		Field float64 `column:"fail,precision:foo"`
	}](t, "float64: invalid parameter")
	expectColumnsFail[struct {
		Field float64 `column:"fail,precision:-2"`
	}](t, "float64: double parameter")
	expectColumnsFail[struct {
		Field string `column:"fail,precision:2"`
	}](t, "invalid field")
}

func TestColumnsWidth(t *testing.T) {
	type testSuccess1 struct {
		FieldWidth     int64 `column:"int,width:4"`
		FieldWidthType int64 `column:"intType,width:type"`
	}

	cols := expectColumnsSuccess[testSuccess1](t)
	expectColumnValue(t, expectColumn(t, cols, "int"), "Width", 4)
	expectColumnValue(t, expectColumn(t, cols, "intType"), "Width", MaxCharsInt64)

	expectColumnsFail[struct {
		Field int64 `column:"fail,width"`
	}](t, "missing parameter")
	expectColumnsFail[struct {
		Field int64 `column:"fail,width:"`
	}](t, "empty parameter")
	expectColumnsFail[struct {
		Field int64 `column:"fail,width:foo"`
	}](t, "invalid parameter")
	expectColumnsFail[struct {
		Field int64 `column:"fail,width:sum:bar"`
	}](t, "double parameter")
}

func TestColumnsMaxWidth(t *testing.T) {
	type testSuccess1 struct {
		FieldMaxWidth     int64 `column:"int,maxWidth:4"`
		FieldMaxWidthType int64 `column:"intType,maxWidth:type"`
	}

	cols := expectColumnsSuccess[testSuccess1](t)

	expectColumnValue(t, expectColumn(t, cols, "int"), "MaxWidth", 4)
	expectColumnValue(t, expectColumn(t, cols, "intType"), "MaxWidth", MaxCharsInt64)

	expectColumnsFail[struct {
		Field int64 `column:"fail,maxWidth"`
	}](t, "missing parameter")
	expectColumnsFail[struct {
		Field int64 `column:"fail,maxWidth:"`
	}](t, "empty parameter")
	expectColumnsFail[struct {
		Field int64 `column:"fail,maxWidth:foo"`
	}](t, "invalid parameter")
	expectColumnsFail[struct {
		Field int64 `column:"fail,maxWidth:sum:bar"`
	}](t, "double parameter")
}

func TestColumnsMinWidth(t *testing.T) {
	type testSuccess1 struct {
		FieldMinWidth     int64 `column:"int,minWidth:4"`
		FieldMaxWidthType int64 `column:"intType,minWidth:type"`
	}

	cols := expectColumnsSuccess[testSuccess1](t)
	expectColumnValue(t, expectColumn(t, cols, "int"), "MinWidth", 4)
	expectColumnValue(t, expectColumn(t, cols, "intType"), "MinWidth", MaxCharsInt64)

	expectColumnsFail[struct {
		Field int64 `column:"fail,minWidth"`
	}](t, "missing parameter")
	expectColumnsFail[struct {
		Field int64 `column:"fail,minWidth:"`
	}](t, "empty parameter")
	expectColumnsFail[struct {
		Field int64 `column:"fail,minWidth:foo"`
	}](t, "invalid parameter")
	expectColumnsFail[struct {
		Field int64 `column:"fail,minWidth:sum:bar"`
	}](t, "double parameter")
}

func TestColumnsWidthFromType(t *testing.T) {
	type testSuccess1 struct {
		Int8   int8   `column:",minWidth:type,maxWidth:type,width:type"`
		Int16  int16  `column:",minWidth:type,maxWidth:type,width:type"`
		Int32  int32  `column:",minWidth:type,maxWidth:type,width:type"`
		Int64  int64  `column:",minWidth:type,maxWidth:type,width:type"`
		Uint8  uint8  `column:",minWidth:type,maxWidth:type,width:type"`
		Uint16 uint16 `column:",minWidth:type,maxWidth:type,width:type"`
		Uint32 uint32 `column:",minWidth:type,maxWidth:type,width:type"`
		Uint64 uint64 `column:",minWidth:type,maxWidth:type,width:type"`
		Bool   bool   `column:",minWidth:type,maxWidth:type,width:type"`
	}

	cols := expectColumnsSuccess[testSuccess1](t)

	col := expectColumn(t, cols, "int8")
	expectColumnValue(t, col, "Width", MaxCharsInt8)
	expectColumnValue(t, col, "MinWidth", MaxCharsInt8)
	expectColumnValue(t, col, "MaxWidth", MaxCharsInt8)

	col = expectColumn(t, cols, "int16")
	expectColumnValue(t, col, "Width", MaxCharsInt16)
	expectColumnValue(t, col, "MinWidth", MaxCharsInt16)
	expectColumnValue(t, col, "MaxWidth", MaxCharsInt16)

	col = expectColumn(t, cols, "int32")
	expectColumnValue(t, col, "Width", MaxCharsInt32)
	expectColumnValue(t, col, "MinWidth", MaxCharsInt32)
	expectColumnValue(t, col, "MaxWidth", MaxCharsInt32)

	col = expectColumn(t, cols, "int64")
	expectColumnValue(t, col, "Width", MaxCharsInt64)
	expectColumnValue(t, col, "MinWidth", MaxCharsInt64)
	expectColumnValue(t, col, "MaxWidth", MaxCharsInt64)

	col = expectColumn(t, cols, "uint8")
	expectColumnValue(t, col, "Width", MaxCharsUint8)
	expectColumnValue(t, col, "MinWidth", MaxCharsUint8)
	expectColumnValue(t, col, "MaxWidth", MaxCharsUint8)

	col = expectColumn(t, cols, "uint16")
	expectColumnValue(t, col, "Width", MaxCharsUint16)
	expectColumnValue(t, col, "MinWidth", MaxCharsUint16)
	expectColumnValue(t, col, "MaxWidth", MaxCharsUint16)

	col = expectColumn(t, cols, "uint32")
	expectColumnValue(t, col, "Width", MaxCharsUint32)
	expectColumnValue(t, col, "MinWidth", MaxCharsUint32)
	expectColumnValue(t, col, "MaxWidth", MaxCharsUint32)

	col = expectColumn(t, cols, "uint64")
	expectColumnValue(t, col, "Width", MaxCharsUint64)
	expectColumnValue(t, col, "MinWidth", MaxCharsUint64)
	expectColumnValue(t, col, "MaxWidth", MaxCharsUint64)

	col = expectColumn(t, cols, "bool")
	expectColumnValue(t, col, "Width", MaxCharsBool)
	expectColumnValue(t, col, "MinWidth", MaxCharsBool)
	expectColumnValue(t, col, "MaxWidth", MaxCharsBool)

	expectColumnsFail[struct {
		String string `column:",minWidth:type,maxWidth:type,width:type"`
	}](t, "invalid field type")
}

func TestWithoutColumnTag(t *testing.T) {
	type Main struct {
		StringField string
		IntField    int
	}

	cols := expectColumnsSuccess[Main](t, WithRequireColumnDefinition(false))

	expectColumn(t, cols, "StringField")
}

func TestColumnFilters(t *testing.T) {
	type Embedded struct {
		EmbeddedString string `column:"embeddedString" columnTags:"test"`
	}
	type Main struct {
		Embedded
		MainString string `column:"mainString" columnTags:"test2"`
		NoTags     string `column:"noTags"`
	}

	cols := expectColumnsSuccess[Main](t)

	expectColumn := func(columnName string, name string, filters ...ColumnFilter) {
		t.Run(name, func(t *testing.T) {
			colMap := cols.GetColumnMap(filters...)
			if _, ok := colMap.GetColumn(columnName); !ok {
				t.Errorf("Expected column %q to exist after applying filters", columnName)
			}
		})
	}

	expectColumn("embeddedString", "embedded or WithTag(test)", Or(WithEmbedded(true), WithTag("test")))
	expectColumn("mainString", "not embedded or WithoutTag(test)", Or(WithEmbedded(false), WithoutTag("test")))
	expectColumn("mainString", "WithTags(test2) and WithoutTags(test)", And(WithTags([]string{"test2"}), WithoutTags([]string{"test"})))
	expectColumn("mainString", "WithTags(test2) and WithoutTags(test)", And(WithTags([]string{"test2"}), WithoutTags([]string{"test"})))

	orderedColumns := cols.GetOrderedColumns(WithoutTags([]string{"test"})) // missing path
	if len(orderedColumns) != 2 || orderedColumns[0].Name != "mainString" {
		t.Errorf("Expected a mainString column after getting ordered columns using filters")
	}

	orderedColumns = cols.GetOrderedColumns(WithNoTags())
	if len(orderedColumns) != 1 || orderedColumns[0].Name != "noTags" {
		t.Errorf("Expected a noTags column after getting ordered columns using filters")
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

	cols := expectColumnsSuccess[Main](t)

	c := expectColumn(t, cols, "embeddedString")
	if !c.IsEmbedded() {
		t.Errorf("Expected the embedded field to be identified as embedded")
	}
	if !c.HasTag("test") {
		t.Errorf("Expected the embedded field to have tag 'test'")
	}
	if c.HasTag("test2") {
		t.Errorf("Didn't expect the embedded field to have tag 'test2'")
	}

	c = expectColumn(t, cols, "mainString")
	if c.IsEmbedded() {
		t.Errorf("Expected mainString to not be identified as embedded")
	}
	if !c.HasTag("test2") {
		t.Errorf("Expected mainString to have tag 'test2'")
	}
	if c.HasTag("test") {
		t.Errorf("Didn't expect mainString to have tag 'test'")
	}
}

func TestColumnTemplates(t *testing.T) {
	if RegisterTemplate("", "width:789") == nil {
		t.Errorf("Expected error because of empty name")
	}
	if RegisterTemplate("demo", "") == nil {
		t.Errorf("Expected error because of empty value")
	}

	if err := RegisterTemplate("numbers", "width:123"); err != nil {
		t.Errorf("Expected success, got %v", err)
	}

	type testSuccess1 struct {
		Int16 int16 `column:",template:numbers"`
		Int32 int32 `column:",template:numbers,width:5"`
		Int64 int64 `column:",template:numbers,hide"`
	}

	cols := expectColumnsSuccess[testSuccess1](t)

	expectColumnValue(t, expectColumn(t, cols, "int16"), "Width", 123)
	expectColumnValue(t, expectColumn(t, cols, "int32"), "Width", 5)
	expectColumnValue(t, expectColumn(t, cols, "int64"), "Width", 123)
	expectColumnValue(t, expectColumn(t, cols, "int64"), "Visible", false)

	expectColumnsFail[struct {
		String string `column:",template"`
	}](t, "not template name given")

	expectColumnsFail[struct {
		String string `column:",template:foobar"`
	}](t, "trying to use non-existing template")
}

func TestColumnTemplatesRegisterExisting(t *testing.T) {
	t.Run("untyped", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("expected panic")
			}
		}()
		MustRegisterTemplate("abc", "width:123")
		MustRegisterTemplate("abc", "width:123")
	})
}
