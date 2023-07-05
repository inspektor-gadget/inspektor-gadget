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

package columns

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestColumnMap(t *testing.T) {
	type testStruct struct {
		StringField string `column:"stringField"`
		IntField    int    `column:"intField"`
	}
	cols := expectColumnsSuccess[testStruct](t)
	columnMap := cols.GetColumnMap()
	assert.Contains(t, columnMap, "stringfield")
	assert.Contains(t, columnMap, "intfield")
}

func TestEmptyStruct(t *testing.T) {
	type testStruct struct {
		StringField string
		IntField    int
	}
	cols := expectColumnsSuccess[testStruct](t)
	require.Empty(t, cols.GetColumnMap())
}

func TestFieldsWithTypeDefinition(t *testing.T) {
	type StringAlias string
	type IntAlias int
	type testStruct struct {
		StringField StringAlias `column:"stringField"`
		IntField    IntAlias    `column:"intField"`
	}

	testVar := &testStruct{
		StringField: "abc",
		IntField:    123,
	}

	cols := expectColumnsSuccess[testStruct](t)
	assert.Equal(t, expectColumn(t, cols, "stringField").Get(testVar).Interface(), testVar.StringField)
	assert.Equal(t, expectColumn(t, cols, "intField").Get(testVar).Interface(), testVar.IntField)
}

func TestGetColumnNames(t *testing.T) {
	type testStruct struct {
		StringField string `column:"stringField,order:500"`
		IntField    int    `column:"intField,order:200"`
	}
	cols := expectColumnsSuccess[testStruct](t).GetColumnNames()
	require.Len(t, cols, 2)
	assert.Equal(t, cols[0], "intField")
	assert.Equal(t, cols[1], "stringField")
}

func TestGetSortedColumns(t *testing.T) {
	type testStruct struct {
		StringField string `column:"stringField,order:500"`
		IntField    int    `column:"intField,order:200"`
	}
	cols := expectColumnsSuccess[testStruct](t).GetOrderedColumns()
	require.Len(t, cols, 2)
	assert.Equal(t, cols[0].Name, "intField")
	assert.Equal(t, cols[1].Name, "stringField")
}

func TestGetters(t *testing.T) {
	type embeddedStruct struct {
		EmbeddedString string `column:"embeddedString"`
	}
	type embeddedPtrStruct struct {
		EmbeddedString2 string `column:"embeddedString2"`
	}
	type ptrStruct struct {
		EmbeddedString string `column:"ptrStructString"`
	}
	type normalStruct struct {
		EmbeddedString string `column:"normalStructString"`
	}
	type testStruct struct {
		embeddedStruct
		*embeddedPtrStruct
		PointerStruct           *ptrStruct
		NormalStruct            normalStruct
		NotEmbeddedPtrStruct    *ptrStruct   `column:"ptrStruct,noembed"`
		NotEmbeddedNormalStruct normalStruct `column:"normalStruct,noembed"`
		StringField             string       `column:"stringField"`
		IntField                int          `column:"intField"`
	}
	cols := expectColumnsSuccess[testStruct](t)

	// String tests
	col := expectColumn(t, cols, "StRiNgFiElD")
	require.Equal(t, col.Kind(), reflect.String)
	_, ok := col.Get(nil).Interface().(string)
	require.True(t, ok, "type should be string")
	str, ok := col.Get(&testStruct{StringField: "demo"}).Interface().(string)
	require.True(t, ok, "type should be string")
	assert.Equal(t, str, "demo")

	// Raw access should return the same
	str, ok = col.GetRaw(&testStruct{StringField: "demo"}).Interface().(string)
	require.True(t, ok, "type should be string")
	assert.Equal(t, str, "demo")

	// Int tests
	col = expectColumn(t, cols, "InTfIeLd")

	i, ok := col.Get(&testStruct{IntField: 5}).Interface().(int)
	require.True(t, ok, "type should be int")
	assert.Equal(t, i, 5)

	_, ok = cols.GetColumn("uNkNoWn")
	require.False(t, ok, "no column should be present")

	// Embedded string tests
	col = expectColumn(t, cols, "embeddedstring")

	_, ok = col.Get(nil).Interface().(string)
	require.True(t, ok, "type should be string")
	str, ok = col.Get(&testStruct{embeddedStruct: embeddedStruct{EmbeddedString: "demo"}}).Interface().(string)
	require.True(t, ok, "type should be string")
	assert.Equal(t, str, "demo")

	// Reflection access
	refStruct := reflect.ValueOf(&testStruct{embeddedStruct: embeddedStruct{EmbeddedString: "demo"}})
	str, ok = col.GetRef(refStruct).Interface().(string)
	require.True(t, ok, "type should be string")
	assert.Equal(t, str, "demo")

	// Embedded (via pointer) string tests
	col = expectColumn(t, cols, "embeddedstring2")

	_, ok = col.Get(nil).Interface().(string)
	require.True(t, ok, "type should be string")
	str, ok = col.Get(&testStruct{embeddedPtrStruct: &embeddedPtrStruct{EmbeddedString2: "demo"}}).Interface().(string)
	require.True(t, ok, "type should be string")
	assert.Equal(t, str, "demo")

	str, ok = col.Get(&testStruct{}).Interface().(string)
	require.True(t, ok, "type should be string")
	assert.Equal(t, str, "")

	// Embedded named structs (via pointer) string tests
	col = expectColumn(t, cols, "ptrStructString")

	_, ok = col.Get(nil).Interface().(string)
	require.True(t, ok, "type should be string")
	str, ok = col.Get(&testStruct{PointerStruct: &ptrStruct{EmbeddedString: "demo"}}).Interface().(string)
	require.True(t, ok, "type should be string")
	assert.Equal(t, str, "demo")

	str, ok = col.Get(&testStruct{}).Interface().(string)
	require.True(t, ok, "type should be string")
	assert.Equal(t, str, "")

	// Embedded named structs (without pointer) string tests
	col = expectColumn(t, cols, "normalStructString")

	_, ok = col.Get(nil).Interface().(string)
	require.True(t, ok, "type should be string")
	str, ok = col.Get(&testStruct{NormalStruct: normalStruct{EmbeddedString: "demo"}}).Interface().(string)
	require.True(t, ok, "type should be string")
	assert.Equal(t, str, "demo")

	str, ok = col.Get(&testStruct{}).Interface().(string)
	require.True(t, ok, "type should be string")
	assert.Equal(t, str, "")

	// Not-Embedded named structs (with pointer) string tests
	col = expectColumn(t, cols, "ptrStruct")

	tmpPtrStruct, ok := col.Get(&testStruct{NotEmbeddedPtrStruct: &ptrStruct{EmbeddedString: "demo"}}).Interface().(*ptrStruct)
	require.True(t, ok, "type should be *ptrStruct")
	assert.Equal(t, tmpPtrStruct.EmbeddedString, "demo")

	// Not-Embedded named structs (without pointer) string tests
	col = expectColumn(t, cols, "normalStruct")

	tmpNormalStruct, ok := col.Get(&testStruct{NotEmbeddedNormalStruct: normalStruct{EmbeddedString: "demo"}}).Interface().(normalStruct)
	require.True(t, ok, "type should be normalStruct")
	assert.Equal(t, tmpNormalStruct.EmbeddedString, "demo")
}

func TestInvalidType(t *testing.T) {
	expectColumnsFail[int](t, "non-struct type int")
}

func TestMustCreateHelper(t *testing.T) {
	type testStruct struct {
		StringField string `column:"stringField"`
	}
	MustCreateColumns[testStruct]()

	defer func() {
		if err := recover(); err == nil {
			t.Errorf("Expected panic")
		}
	}()
	MustCreateColumns[int]()
}

func TestExtractor(t *testing.T) {
	type testStruct struct {
		StringField string `column:"stringField"`
	}
	cols := expectColumnsSuccess[testStruct](t)
	assert.NoError(t, cols.SetExtractor("sTrInGfIeLd", func(t *testStruct) string {
		return "empty"
	}))
	assert.Error(t, cols.SetExtractor("unknown", func(t *testStruct) string {
		return "empty"
	}), "should return error when trying to set extractor for non-existent field")
	assert.Error(
		t,
		cols.SetExtractor("sTrInGfIeLd", nil),
		"should return error when no extractor has been set",
	)
}

type Uint32 uint32

func (v Uint32) String() string {
	return fmt.Sprintf("%d-from-stringer", v)
}

func TestStringer(t *testing.T) {
	type testStruct struct {
		StringerField Uint32 `column:"stringerField,stringer"`
	}
	cols := expectColumnsSuccess[testStruct](t)
	col := expectColumn(t, cols, "stringerField")

	ts := &testStruct{StringerField: 12345}

	val, ok := col.Get(ts).Interface().(string)
	require.True(t, ok, "type should be string")
	assert.Equal(t, val, "12345-from-stringer")
}

func TestVirtualColumns(t *testing.T) {
	type testStruct struct {
		StringField string `column:"stringField"`
	}

	cols := expectColumnsSuccess[testStruct](t)

	assert.Error(t, cols.AddColumn(Attributes{
		Name: "vcol",
	}, nil), "should return error when adding a column without extractor func")

	assert.Error(t, cols.AddColumn(Attributes{}, func(_ *testStruct) string {
		return ""
	}), "should return error when adding a column without name")

	assert.Error(t, cols.AddColumn(Attributes{
		Name: "stringfield",
	}, func(_ *testStruct) string {
		return ""
	}), "should return error when adding a column with already existing name")

	assert.NoError(t, cols.AddColumn(Attributes{
		Name: "foobar",
	}, func(t *testStruct) string {
		return "FooBar"
	}))

	col := expectColumn(t, cols, "foobar")
	_, ok := col.Get(nil).Interface().(string)
	require.True(t, ok, "type should be string")
	str, ok := col.Get(&testStruct{}).Interface().(string)
	require.True(t, ok, "type should be string")
	assert.Equal(t, str, "FooBar")

	// Test GetRef also
	str, ok = col.GetRef(reflect.ValueOf(&testStruct{})).Interface().(string)
	require.True(t, ok, "type should be string")
	assert.Equal(t, str, "FooBar")

	// Raw access should return an empty string
	str, ok = col.GetRaw(&testStruct{}).Interface().(string)
	require.True(t, ok, "type should be string")
	assert.Equal(t, str, "", "should be empty on a virtual column")
}

func TestVerifyColumnNames(t *testing.T) {
	type testStruct struct {
		StringField string `column:"stringField"`
		IntField    string `column:"intField"`
	}

	cols := expectColumnsSuccess[testStruct](t)

	valid, invalid := cols.VerifyColumnNames([]string{"-stringField", "intField", "notExistingField", "notExistingField2"})
	assert.Len(t, valid, 2)
	assert.Len(t, invalid, 2)
}

func TestEmbeddedStructs(t *testing.T) {
	type embeddedStructUnnamed struct {
		foo int `column:"foo"`
	}
	type embeddedStructNamed struct {
		foo int `column:"foo"`
	}
	type embeddedStructNamedWithTemplate struct {
		foo int `column:"foo,template:bar"`
	}
	type testStruct struct {
		embeddedStructUnnamed
		embeddedStructNamed             `column:"named" columnTags:"abc,def"`
		embeddedStructNamedWithTemplate `column:"withTemplate" columnTags:"ghi"`
	}

	assert.NoError(t, RegisterTemplate("bar", "width:123"))

	cols := MustCreateColumns[testStruct]()

	_, found := cols.GetColumn("embeddedStructUnnamed.foo")
	assert.False(t, found)

	fooCol, found := cols.GetColumn("foo")
	require.True(t, found)
	assert.Equal(t, fooCol.Name, "foo")

	_, found = cols.GetColumn("embeddedStructNamed.foo")
	assert.False(t, found)

	fooCol, found = cols.GetColumn("named.foo")
	require.True(t, found)
	assert.Equal(t, fooCol.Name, "named.foo")

	assert.Contains(t, fooCol.Tags, "def", "tags from parent should be inherited")

	_, found = cols.GetColumn("embeddedStructNamedWithTemplate.foo")
	assert.False(t, found)

	fooCol, found = cols.GetColumn("withTemplate.foo")
	require.True(t, found)
	assert.Equal(t, fooCol.Name, "withTemplate.foo")

	assert.Contains(t, fooCol.Tags, "ghi", "tags from parent should be inherited")

	expectColumnValue(t, expectColumn(t, cols, "withTemplate.foo"), "Width", 123)
}

func TestFieldFuncs(t *testing.T) {
	type testStruct struct {
		stringField   string    `column:"stringField"`
		uint8ArrField [16]uint8 `column:"uint8ArrField"`
	}

	testInstance := &testStruct{
		stringField:   "foo",
		uint8ArrField: [16]uint8{}, // Will be setup by copy
	}
	copy(testInstance.uint8ArrField[:], []uint8("foobarbaz\x00asdfgh"))

	cols := MustCreateColumns[testStruct]()

	stringFieldCol, _ := cols.GetColumn("stringField")
	stringFieldFunc := GetFieldFunc[string, testStruct](stringFieldCol)
	assert.Equal(t, "foo", stringFieldFunc(testInstance))
	uint8ArrFieldCol, _ := cols.GetColumn("uint8ArrField")
	uint8ArrFieldFunc := GetFieldAsArrayFunc[uint8, testStruct](uint8ArrFieldCol)
	assert.Equal(t, "foobarbaz\x00asdfgh", string(uint8ArrFieldFunc(testInstance)))
	uint8ArrFieldStringFunc := GetFieldAsString[testStruct](uint8ArrFieldCol)
	assert.Equal(t, "foobarbaz", uint8ArrFieldStringFunc(testInstance))
}
