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
	"fmt"
	"reflect"
	"testing"
)

func TestColumnMap(t *testing.T) {
	type testStruct struct {
		StringField string `column:"stringField"`
		IntField    int    `column:"intField"`
	}
	cols := expectColumnsSuccess[testStruct](t)
	columnMap := cols.GetColumnMap()
	if _, ok := columnMap["stringfield"]; !ok {
		t.Errorf("Expected stringfield in column map")
	}
	if _, ok := columnMap["intfield"]; !ok {
		t.Errorf("Expected intfield in column map")
	}
}

func TestEmptyStruct(t *testing.T) {
	type testStruct struct {
		StringField string
		IntField    int
	}
	cols := expectColumnsSuccess[testStruct](t)
	columnMap := cols.GetColumnMap()
	if len(columnMap) != 0 {
		t.Errorf("Expected empty column map")
	}
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
	if expectColumn(t, cols, "stringField").Get(testVar).Interface() != testVar.StringField {
		t.Errorf("expected stringField to contain %q", testVar.StringField)
	}
	if expectColumn(t, cols, "intField").Get(testVar).Interface() != testVar.IntField {
		t.Errorf("expected intField to contain %q", testVar.IntField)
	}
}

func TestGetColumnNames(t *testing.T) {
	type testStruct struct {
		StringField string `column:"stringField,order:500"`
		IntField    int    `column:"intField,order:200"`
	}
	ocols := expectColumnsSuccess[testStruct](t).GetColumnNames()
	if len(ocols) != 2 {
		t.Fatalf("Expected two columns")
	}
	if ocols[0] != "intField" {
		t.Errorf("Expected first entry to be intField")
	}
	if ocols[1] != "stringField" {
		t.Errorf("Expected second entry to be stringField")
	}
}

func TestGetSortedColumns(t *testing.T) {
	type testStruct struct {
		StringField string `column:"stringField,order:500"`
		IntField    int    `column:"intField,order:200"`
	}
	ocols := expectColumnsSuccess[testStruct](t).GetOrderedColumns()
	if len(ocols) != 2 {
		t.Fatalf("Expected two columns")
	}
	if ocols[0].Name != "intField" {
		t.Errorf("Expected first entry to be intField")
	}
	if ocols[1].Name != "stringField" {
		t.Errorf("Expected second entry to be stringField")
	}
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
	if col.Kind() != reflect.String {
		t.Errorf("Expected Kind() to be reflect.String")
	}
	_, ok := col.Get(nil).Interface().(string)
	if !ok {
		t.Errorf("Expected returned value to be of type string")
	}
	str, ok := col.Get(&testStruct{StringField: "demo"}).Interface().(string)
	if !ok {
		t.Errorf("Expected returned value to be of type string")
	}
	if str != "demo" {
		t.Errorf("Expected returned value to be string 'demo'")
	}
	// Raw access should return the same
	str, ok = col.GetRaw(&testStruct{StringField: "demo"}).Interface().(string)
	if !ok {
		t.Errorf("Expected returned value to be of type string")
	}
	if str != "demo" {
		t.Errorf("Expected returned value to be string 'demo'")
	}

	// Int tests
	col = expectColumn(t, cols, "InTfIeLd")

	i, ok := col.Get(&testStruct{IntField: 5}).Interface().(int)
	if !ok {
		t.Errorf("Expected returned value to be of type int")
	}
	if i != 5 {
		t.Errorf("Expected returned value to be int with value 5")
	}

	_, ok = cols.GetColumn("uNkNoWn")
	if ok {
		t.Errorf("Expected no column")
	}

	// Embedded string tests
	col = expectColumn(t, cols, "embeddedstring")

	_, ok = col.Get(nil).Interface().(string)
	if !ok {
		t.Errorf("Expected returned value to be of type string")
	}
	str, ok = col.Get(&testStruct{embeddedStruct: embeddedStruct{EmbeddedString: "demo"}}).Interface().(string)
	if !ok {
		t.Errorf("Expected returned value to be of type string")
	}
	if str != "demo" {
		t.Errorf("Expected returned value to be string 'demo'")
	}

	// Reflection access
	refStruct := reflect.ValueOf(&testStruct{embeddedStruct: embeddedStruct{EmbeddedString: "demo"}})
	str, ok = col.GetRef(refStruct).Interface().(string)
	if !ok {
		t.Errorf("Expected returned value to be of type string, got %+v", col.GetRef(refStruct).Interface())
	}
	if str != "demo" {
		t.Errorf("Expected returned value to be string 'demo'")
	}

	// Embedded (via pointer) string tests
	col = expectColumn(t, cols, "embeddedstring2")

	_, ok = col.Get(nil).Interface().(string)
	if !ok {
		t.Errorf("Expected returned value to be of type string")
	}
	str, ok = col.Get(&testStruct{embeddedPtrStruct: &embeddedPtrStruct{EmbeddedString2: "demo"}}).Interface().(string)
	if !ok {
		t.Errorf("Expected returned value to be of type string")
	}
	if str != "demo" {
		t.Errorf("Expected returned value to be string 'demo'")
	}

	str, ok = col.Get(&testStruct{}).Interface().(string)
	if !ok {
		t.Errorf("Expected returned value to be of type string, got %+v", col.Get(&testStruct{}).Interface())
	}
	if str != "" {
		t.Errorf("Expected returned value to be an empty string")
	}

	// Embedded named structs (via pointer) string tests
	col = expectColumn(t, cols, "ptrStructString")

	_, ok = col.Get(nil).Interface().(string)
	if !ok {
		t.Errorf("Expected returned value to be of type string")
	}
	str, ok = col.Get(&testStruct{PointerStruct: &ptrStruct{EmbeddedString: "demo"}}).Interface().(string)
	if !ok {
		t.Errorf("Expected returned value to be of type string")
	}
	if str != "demo" {
		t.Errorf("Expected returned value to be string 'demo'")
	}

	str, ok = col.Get(&testStruct{}).Interface().(string)
	if !ok {
		t.Errorf("Expected returned value to be of type string, got %+v", col.Get(&testStruct{}).Interface())
	}
	if str != "" {
		t.Errorf("Expected returned value to be an empty string")
	}

	// Embedded named structs (without pointer) string tests
	col = expectColumn(t, cols, "normalStructString")

	_, ok = col.Get(nil).Interface().(string)
	if !ok {
		t.Errorf("Expected returned value to be of type string")
	}
	str, ok = col.Get(&testStruct{NormalStruct: normalStruct{EmbeddedString: "demo"}}).Interface().(string)
	if !ok {
		t.Errorf("Expected returned value to be of type string")
	}
	if str != "demo" {
		t.Errorf("Expected returned value to be string 'demo'")
	}

	str, ok = col.Get(&testStruct{}).Interface().(string)
	if !ok {
		t.Errorf("Expected returned value to be of type string, got %+v", col.Get(&testStruct{}).Interface())
	}
	if str != "" {
		t.Errorf("Expected returned value to be an empty string")
	}

	// Not-Embedded named structs (with pointer) string tests
	col = expectColumn(t, cols, "ptrStruct")

	tmpPtrStruct, ok := col.Get(&testStruct{NotEmbeddedPtrStruct: &ptrStruct{EmbeddedString: "demo"}}).Interface().(*ptrStruct)
	if !ok {
		t.Errorf("Expected returned value to be of type *ptrStruct")
	}
	if tmpPtrStruct.EmbeddedString != "demo" {
		t.Errorf("Expected returned value to be string 'demo'")
	}

	// Not-Embedded named structs (without pointer) string tests
	col = expectColumn(t, cols, "normalStruct")

	tmpNormalStruct, ok := col.Get(&testStruct{NotEmbeddedNormalStruct: normalStruct{EmbeddedString: "demo"}}).Interface().(normalStruct)
	if !ok {
		t.Errorf("Expected returned value to be of type normalStruct")
	}
	if tmpNormalStruct.EmbeddedString != "demo" {
		t.Errorf("Expected returned value to be string 'demo'")
	}
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

	err := cols.SetExtractor("sTrInGfIeLd", func(t *testStruct) string {
		return "empty"
	})
	if err != nil {
		t.Errorf("could not set extractor: %v", err)
	}

	err = cols.SetExtractor("unknown", func(t *testStruct) string {
		return "empty"
	})
	if err == nil {
		t.Errorf("Expected error when setting extractor on non-existing field")
	}

	err = cols.SetExtractor("sTrInGfIeLd", nil)
	if err == nil {
		t.Errorf("Expected error when setting nil-extractor")
	}
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
	if !ok {
		t.Fatalf("expected type string")
	}
	if val != "12345-from-stringer" {
		t.Errorf("expected proper return value from stringer, got %q", val)
	}
}

func TestVirtualColumns(t *testing.T) {
	type testStruct struct {
		StringField string `column:"stringField"`
	}

	cols := expectColumnsSuccess[testStruct](t)

	err := cols.AddColumn(Column[testStruct]{
		Name: "vcol",
	})
	if err == nil {
		t.Errorf("Expected error when adding column without extractor func")
	}

	err = cols.AddColumn(Column[testStruct]{
		Extractor: func(_ *testStruct) string {
			return ""
		},
	})
	if err == nil {
		t.Errorf("Expected error when adding column without name")
	}

	err = cols.AddColumn(Column[testStruct]{
		Name: "stringfield",
		Extractor: func(_ *testStruct) string {
			return ""
		},
	})
	if err == nil {
		t.Errorf("Expected error when adding column with already existing name")
	}

	err = cols.AddColumn(Column[testStruct]{
		Name: "foobar",
		Extractor: func(t *testStruct) string {
			return "FooBar"
		},
	})
	if err != nil {
		t.Errorf("could not add virtual column")
	}

	col := expectColumn(t, cols, "foobar")
	_, ok := col.Get(nil).Interface().(string)
	if !ok {
		t.Errorf("Expected returned value to be of type string")
	}
	str, ok := col.Get(&testStruct{}).Interface().(string)
	if !ok {
		t.Errorf("Expected returned value to be of type string")
	}
	if str != "FooBar" {
		t.Errorf("Expected returned value to be string 'FooBar'")
	}

	// Test GetRef also
	str, ok = col.GetRef(reflect.ValueOf(&testStruct{})).Interface().(string)
	if !ok {
		t.Errorf("Expected returned value to be of type string")
	}
	if str != "FooBar" {
		t.Errorf("Expected returned value to be string 'FooBar'")
	}

	// Raw access should return an empty string
	str, ok = col.GetRaw(&testStruct{}).Interface().(string)
	if !ok {
		t.Errorf("Expected returned value to be of type string")
	}
	if str != "" {
		t.Errorf("Expected empty string when calling GetRaw() on a virtual column")
	}
}

func TestVerifyColumnNames(t *testing.T) {
	type testStruct struct {
		StringField string `column:"stringField"`
		IntField    string `column:"intField"`
	}

	cols := expectColumnsSuccess[testStruct](t)

	valid, invalid := cols.VerifyColumnNames([]string{"-stringField", "intField", "notExistingField", "notExistingField2"})
	if len(valid) != 2 {
		t.Errorf("Expected VerifyColumnNames to return 2 valid entries")
	}
	if len(invalid) != 2 {
		t.Errorf("Expected VerifyColumnNames to return 2 invalid entries")
	}
}
