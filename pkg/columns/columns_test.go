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
		t.Errorf("Expected stringfield in column map")
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
	type testStruct struct {
		embeddedStruct
		StringField string `column:"stringField"`
		IntField    int    `column:"intField"`
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
		t.Errorf("Expected returned value to be of type string")
	}
	if str != "demo" {
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
