// Copyright 2024 The Inspektor Gadget authors
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

package expr

import (
	"testing"

	"github.com/expr-lang/expr"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

type testCaseString struct {
	name         string
	filterString string
	result       string
	error        bool
}

type testCaseFilter struct {
	name         string
	filterString string
	match        bool
	error        bool
}

type testCaseData struct {
	stringValue  string
	int64Value   int64
	float64Value float64
	boolValue    bool
}

func TestExpressionString(t *testing.T) {
	testCaseData := testCaseData{
		stringValue:  "abc",
		int64Value:   123,
		float64Value: 456.0,
		boolValue:    true,
	}

	testCases := []testCaseString{
		// Existing test cases
		{
			name:         "concat string",
			filterString: "\"hello \"+stringValue",
			error:        false,
			result:       "hello abc",
		},
		{
			name:         "all of them",
			filterString: "\"hello \"+stringValue+\", the int64 is \"+string(int64Value)+\", the float is \"+string(float64Value)+\", and the bool is \"+string(boolValue)",
			error:        false,
			result:       "hello abc, the int64 is 123, the float is 456, and the bool is true",
		},
		// New test cases
		{
			name:         "string direct access",
			filterString: "stringValue",
			error:        false,
			result:       "abc",
		},
		{
			name:         "int to string conversion",
			filterString: "string(int64Value)",
			error:        false,
			result:       "123",
		},
		{
			name:         "float to string conversion",
			filterString: "string(float64Value)",
			error:        false,
			result:       "456",
		},
		{
			name:         "bool to string conversion",
			filterString: "string(boolValue)",
			error:        false,
			result:       "true",
		},
		{
			name:         "invalid string operation",
			filterString: "stringValue + int64Value",
			error:        true,
		},
		{
			name:         "empty string",
			filterString: "",
			error:        true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var stringField datasource.FieldAccessor
			var int64Field datasource.FieldAccessor
			var float64Field datasource.FieldAccessor
			var boolField datasource.FieldAccessor

			ds, err := datasource.New(datasource.TypeSingle, "filter")
			require.NoError(t, err)
			stringField, err = ds.AddField("stringValue", api.Kind_String)
			require.NoError(t, err)
			int64Field, err = ds.AddField("int64Value", api.Kind_Int64)
			require.NoError(t, err)
			float64Field, err = ds.AddField("float64Value", api.Kind_Float64)
			require.NoError(t, err)
			boolField, err = ds.AddField("boolValue", api.Kind_Bool)
			require.NoError(t, err)

			data, err := ds.NewPacketSingle()
			require.NoError(t, err)
			err = stringField.PutString(data, testCaseData.stringValue)
			require.NoError(t, err)
			err = int64Field.PutInt64(data, testCaseData.int64Value)
			require.NoError(t, err)
			err = float64Field.PutFloat64(data, testCaseData.float64Value)
			require.NoError(t, err)
			err = boolField.PutBool(data, testCaseData.boolValue)
			require.NoError(t, err)

			filter, err := CompileStringProgram(ds, tc.filterString)
			if tc.error {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			res, err := expr.Run(filter, wrap{d: data})
			require.NoError(t, err)

			require.Equal(t, tc.result, res.(string), tc.name)
		})
	}
}

func TestExpressionFilter(t *testing.T) {
	testCaseData := testCaseData{
		stringValue:  "abc",
		int64Value:   123,
		float64Value: 456.0,
		boolValue:    true,
	}
	testCases := []testCaseFilter{
		{
			name:         "incomplete filter",
			filterString: "abc",
			error:        true,
		},
		{
			name:         "string match positive",
			filterString: "stringValue=='abc'",
			match:        true,
		},
		{
			name:         "string match negative",
			filterString: "stringValue=='def'",
			match:        false,
		},
		{
			name:         "string not match positive",
			filterString: "stringValue!='def'",
			match:        true,
		},
		{
			name:         "string not match negative",
			filterString: "stringValue!='abc'",
			match:        false,
		},
		{
			name:         "string lte positive",
			filterString: "stringValue<='def'",
			match:        true,
		},
		{
			name:         "string gte negative",
			filterString: "stringValue>='def'",
			match:        false,
		},
		{
			name:         "string regex match positive",
			filterString: "stringValue matches 'a..'",
			match:        true,
		},
		{
			name:         "string regex match negative",
			filterString: "stringValue matches 'b..'",
			match:        false,
		},
		{
			name:         "string regex not match positive",
			filterString: "stringValue not matches 'b..'",
			match:        true,
		},
		{
			name:         "string regex not match negative",
			filterString: "stringValue not matches 'a..'",
			match:        false,
		},
		{
			name:         "string regex invalid",
			filterString: "stringValue matches '???a..'",
			error:        true,
		},

		{
			name:         "int match positive",
			filterString: "int64Value==123",
			match:        true,
		},
		{
			name:         "int match negative",
			filterString: "int64Value==345",
			match:        false,
		},
		{
			name:         "int gte positive",
			filterString: "int64Value>=1",
			match:        true,
		},
		{
			name:         "int gte positive",
			filterString: "int64Value>=123",
			match:        true,
		},
		{
			name:         "int gte negative",
			filterString: "int64Value>=1000",
			match:        false,
		},
		{
			name:         "int lte positive",
			filterString: "int64Value<=1000",
			match:        true,
		},
		{
			name:         "int lte positive",
			filterString: "int64Value<=123",
			match:        true,
		},
		{
			name:         "int lte negative",
			filterString: "int64Value<=1",
			match:        false,
		},
		{
			name:         "int gt positive",
			filterString: "int64Value>=1",
			match:        true,
		},
		{
			name:         "int gt negative",
			filterString: "int64Value>=1000",
			match:        false,
		},
		{
			name:         "int lt positive",
			filterString: "int64Value>1",
			match:        true,
		},
		{
			name:         "int lt negative",
			filterString: "int64Value>1000",
			match:        false,
		},
		{
			name:         "int no int",
			filterString: "int64Value>'abc'",
			error:        true,
		},

		{
			name:         "float match positive",
			filterString: "float64Value==456",
			match:        true,
		},
		{
			name:         "float match positive",
			filterString: "float64Value==456.0",
			match:        true,
		},
		{
			name:         "float match negative",
			filterString: "float64Value==345",
			match:        false,
		},
		{
			name:         "float match negative",
			filterString: "float64Value==456.8",
			match:        false,
		},
		{
			name:         "float gte positive",
			filterString: "float64Value>=1",
			match:        true,
		},
		{
			name:         "float gte positive",
			filterString: "float64Value>=456",
			match:        true,
		},
		{
			name:         "float gte negative",
			filterString: "float64Value>=1000",
			match:        false,
		},
		{
			name:         "float lte positive",
			filterString: "float64Value<=1000",
			match:        true,
		},
		{
			name:         "float lte positive",
			filterString: "float64Value<=456",
			match:        true,
		},
		{
			name:         "float lte negative",
			filterString: "float64Value<=1",
			match:        false,
		},
		{
			name:         "float gt positive",
			filterString: "float64Value>=1.0",
			match:        true,
		},
		{
			name:         "float gt negative",
			filterString: "float64Value>=1000.0",
			match:        false,
		},
		{
			name:         "float lt positive",
			filterString: "float64Value>1.0",
			match:        true,
		},
		{
			name:         "float lt negative",
			filterString: "float64Value>1000.0",
			match:        false,
		},
		{
			name:         "float no float",
			filterString: "float64Value>'abc'",
			error:        true,
		},

		{
			name:         "bool match positive",
			filterString: "boolValue==true",
			match:        true,
		},
		{
			name:         "bool match negative",
			filterString: "boolValue==false",
			match:        false,
		},
		{
			name:         "bool not match positive",
			filterString: "boolValue!=false",
			match:        true,
		},
		{
			name:         "bool not match negative",
			filterString: "boolValue!=true",
			match:        false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var stringField datasource.FieldAccessor
			var int64Field datasource.FieldAccessor
			var float64Field datasource.FieldAccessor
			var boolField datasource.FieldAccessor

			ds, err := datasource.New(datasource.TypeSingle, "filter")
			require.NoError(t, err)
			stringField, err = ds.AddField("stringValue", api.Kind_String)
			require.NoError(t, err)
			int64Field, err = ds.AddField("int64Value", api.Kind_Int64)
			require.NoError(t, err)
			float64Field, err = ds.AddField("float64Value", api.Kind_Float64)
			require.NoError(t, err)
			boolField, err = ds.AddField("boolValue", api.Kind_Bool)
			require.NoError(t, err)

			data, err := ds.NewPacketSingle()
			require.NoError(t, err)
			err = stringField.PutString(data, testCaseData.stringValue)
			require.NoError(t, err)
			err = int64Field.PutInt64(data, testCaseData.int64Value)
			require.NoError(t, err)
			err = float64Field.PutFloat64(data, testCaseData.float64Value)
			require.NoError(t, err)
			err = boolField.PutBool(data, testCaseData.boolValue)
			require.NoError(t, err)

			filter, err := CompileFilterProgram(ds, tc.filterString)
			if tc.error {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			res, err := expr.Run(filter, wrap{d: data})
			require.NoError(t, err)

			require.Equal(t, tc.match, res.(bool), tc.name)
		})
	}
}

func TestExpressionBadPath(t *testing.T) {
	ds, err := datasource.New(datasource.TypeSingle, "error_test")
	require.NoError(t, err)

	stringField, err := ds.AddField("stringVal", api.Kind_String)
	require.NoError(t, err)

	data, err := ds.NewPacketSingle()
	require.NoError(t, err)

	err = stringField.PutString(data, "test")
	require.NoError(t, err)

	testCases := []struct {
		name        string
		expr        string
		useFilter   bool // if true, use CompileFilterProgram, otherwise use CompileStringProgram
		shouldError bool
	}{
		{
			name:        "invalid field reference",
			expr:        "nonexistentField",
			useFilter:   false,
			shouldError: true,
		},
		{
			name:        "invalid expression syntax",
			expr:        "stringVal + )",
			useFilter:   false,
			shouldError: true,
		},
		{
			name:        "empty expression",
			expr:        "",
			useFilter:   false,
			shouldError: true,
		},
		{
			name:        "type mismatch operation",
			expr:        "stringVal > 5",
			useFilter:   true,
			shouldError: true,
		},
		{
			name:        "invalid filter syntax",
			expr:        "stringVal === true",
			useFilter:   true,
			shouldError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.useFilter {
				_, err = CompileFilterProgram(ds, tc.expr)
			} else {
				_, err = CompileStringProgram(ds, tc.expr)
			}
			if tc.shouldError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDsPatcher_MemberFieldAccess(t *testing.T) {
	ds, err := datasource.New(datasource.TypeSingle, "member_test")
	require.NoError(t, err)

	// Add a parent field
	parentField, err := ds.AddField("parent", api.Kind_String)
	require.NoError(t, err)

	// Add subfields using AddSubField
	child1, err := parentField.AddSubField("child1", api.Kind_String)
	require.NoError(t, err)
	child2, err := parentField.AddSubField("child2", api.Kind_Int64)
	require.NoError(t, err)

	data, err := ds.NewPacketSingle()
	require.NoError(t, err)

	err = child1.PutString(data, "child1_value")
	require.NoError(t, err)
	err = child2.PutInt64(data, 42)
	require.NoError(t, err)

	// Test string access
	stringTestCases := []struct {
		name     string
		expr     string
		expected string
		hasError bool
	}{
		{
			name:     "access child1",
			expr:     "parent.child1",
			expected: "child1_value",
		},
		{
			name:     "string expression with child1",
			expr:     `"prefix_" + parent.child1`,
			expected: "prefix_child1_value",
		},
	}

	for _, tc := range stringTestCases {
		t.Run(tc.name, func(t *testing.T) {
			prog, err := CompileStringProgram(ds, tc.expr)
			if tc.hasError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			result, err := Run(prog, data)
			require.NoError(t, err)
			require.Equal(t, tc.expected, result)
		})
	}

	// Test filter/boolean operations
	filterTestCases := []struct {
		name     string
		expr     string
		expected bool
		hasError bool
	}{
		{
			name:     "compare child2",
			expr:     "parent.child2 == 42",
			expected: true,
		},
		{
			name:     "invalid comparison",
			expr:     "parent.child1 > parent.child2",
			hasError: true,
		},
	}

	for _, tc := range filterTestCases {
		t.Run(tc.name, func(t *testing.T) {
			prog, err := CompileFilterProgram(ds, tc.expr)
			if tc.hasError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			result, err := Run(prog, data)
			require.NoError(t, err)
			require.Equal(t, tc.expected, result)
		})
	}
}

func TestWrapGetFunctions(t *testing.T) {
	ds, err := datasource.New(datasource.TypeSingle, "get_test")
	require.NoError(t, err)

	// Add fields for all numeric types
	uint8Field, err := ds.AddField("uint8", api.Kind_Uint8)
	require.NoError(t, err)
	uint16Field, err := ds.AddField("uint16", api.Kind_Uint16)
	require.NoError(t, err)
	uint32Field, err := ds.AddField("uint32", api.Kind_Uint32)
	require.NoError(t, err)
	uint64Field, err := ds.AddField("uint64", api.Kind_Uint64)
	require.NoError(t, err)
	int8Field, err := ds.AddField("int8", api.Kind_Int8)
	require.NoError(t, err)
	int16Field, err := ds.AddField("int16", api.Kind_Int16)
	require.NoError(t, err)
	int32Field, err := ds.AddField("int32", api.Kind_Int32)
	require.NoError(t, err)
	int64Field, err := ds.AddField("int64", api.Kind_Int64)
	require.NoError(t, err)
	float32Field, err := ds.AddField("float32", api.Kind_Float32)
	require.NoError(t, err)
	float64Field, err := ds.AddField("float64", api.Kind_Float64)
	require.NoError(t, err)

	data, err := ds.NewPacketSingle()
	require.NoError(t, err)

	// Put test values
	err = uint8Field.PutUint8(data, 8)
	require.NoError(t, err)
	err = uint16Field.PutUint16(data, 16)
	require.NoError(t, err)
	err = uint32Field.PutUint32(data, 32)
	require.NoError(t, err)
	err = uint64Field.PutUint64(data, 64)
	require.NoError(t, err)
	err = int8Field.PutInt8(data, -8)
	require.NoError(t, err)
	err = int16Field.PutInt16(data, -16)
	require.NoError(t, err)
	err = int32Field.PutInt32(data, -32)
	require.NoError(t, err)
	err = int64Field.PutInt64(data, -64)
	require.NoError(t, err)
	err = float32Field.PutFloat32(data, 32.5)
	require.NoError(t, err)
	err = float64Field.PutFloat64(data, 64.5)
	require.NoError(t, err)

	w := wrap{d: data}

	// Test each Get function
	t.Run("GetUint8", func(t *testing.T) {
		res := w.GetUint8(uint8Field)
		require.Equal(t, uint8(8), res)
	})

	t.Run("GetUint16", func(t *testing.T) {
		res := w.GetUint16(uint16Field)
		require.Equal(t, uint16(16), res)
	})

	t.Run("GetUint32", func(t *testing.T) {
		res := w.GetUint32(uint32Field)
		require.Equal(t, uint32(32), res)
	})

	t.Run("GetUint64", func(t *testing.T) {
		res := w.GetUint64(uint64Field)
		require.Equal(t, uint64(64), res)
	})

	t.Run("GetInt8", func(t *testing.T) {
		res := w.GetInt8(int8Field)
		require.Equal(t, int8(-8), res)
	})

	t.Run("GetInt16", func(t *testing.T) {
		res := w.GetInt16(int16Field)
		require.Equal(t, int16(-16), res)
	})

	t.Run("GetInt32", func(t *testing.T) {
		res := w.GetInt32(int32Field)
		require.Equal(t, int32(-32), res)
	})

	t.Run("GetInt64", func(t *testing.T) {
		res := w.GetInt64(int64Field)
		require.Equal(t, int64(-64), res)
	})

	t.Run("GetFloat32", func(t *testing.T) {
		res := w.GetFloat32(float32Field)
		require.Equal(t, float32(32.5), res)
	})

	t.Run("GetFloat64", func(t *testing.T) {
		res := w.GetFloat64(float64Field)
		require.Equal(t, float64(64.5), res)
	})
}

func TestExpressionArithmetic(t *testing.T) {
	ds, err := datasource.New(datasource.TypeSingle, "arithmetic_test")
	require.NoError(t, err)

	// Add fields for all numeric types
	uint8Field, err := ds.AddField("uint8", api.Kind_Uint8)
	require.NoError(t, err)
	uint16Field, err := ds.AddField("uint16", api.Kind_Uint16)
	require.NoError(t, err)
	uint32Field, err := ds.AddField("uint32", api.Kind_Uint32)
	require.NoError(t, err)
	uint64Field, err := ds.AddField("uint64", api.Kind_Uint64)
	require.NoError(t, err)
	int8Field, err := ds.AddField("int8", api.Kind_Int8)
	require.NoError(t, err)
	int16Field, err := ds.AddField("int16", api.Kind_Int16)
	require.NoError(t, err)
	int32Field, err := ds.AddField("int32", api.Kind_Int32)
	require.NoError(t, err)
	int64Field, err := ds.AddField("int64", api.Kind_Int64)
	require.NoError(t, err)
	float32Field, err := ds.AddField("float32", api.Kind_Float32)
	require.NoError(t, err)
	float64Field, err := ds.AddField("float64", api.Kind_Float64)
	require.NoError(t, err)

	data, err := ds.NewPacketSingle()
	require.NoError(t, err)

	// Put test values
	err = uint8Field.PutUint8(data, 8)
	require.NoError(t, err)
	err = uint16Field.PutUint16(data, 16)
	require.NoError(t, err)
	err = uint32Field.PutUint32(data, 32)
	require.NoError(t, err)
	err = uint64Field.PutUint64(data, 64)
	require.NoError(t, err)
	err = int8Field.PutInt8(data, -8)
	require.NoError(t, err)
	err = int16Field.PutInt16(data, -16)
	require.NoError(t, err)
	err = int32Field.PutInt32(data, -32)
	require.NoError(t, err)
	err = int64Field.PutInt64(data, -64)
	require.NoError(t, err)
	err = float32Field.PutFloat32(data, 32.5)
	require.NoError(t, err)
	err = float64Field.PutFloat64(data, 64.5)
	require.NoError(t, err)

	// Test arithmetic expressions for each type
	testCases := []struct {
		name         string
		filterString string
		expected     bool
	}{
		{
			name:         "uint8 arithmetic",
			filterString: "uint8 * 2 == 16",
			expected:     true,
		},
		{
			name:         "uint16 arithmetic",
			filterString: "uint16 * 2 == 32",
			expected:     true,
		},
		{
			name:         "uint32 arithmetic",
			filterString: "uint32 * 2 == 64",
			expected:     true,
		},
		{
			name:         "uint64 arithmetic",
			filterString: "uint64 * 2 == 128",
			expected:     true,
		},
		{
			name:         "int8 arithmetic",
			filterString: "int8 * 2 == -16",
			expected:     true,
		},
		{
			name:         "int16 arithmetic",
			filterString: "int16 * 2 == -32",
			expected:     true,
		},
		{
			name:         "int32 arithmetic",
			filterString: "int32 * 2 == -64",
			expected:     true,
		},
		{
			name:         "int64 arithmetic",
			filterString: "int64 * 2 == -128",
			expected:     true,
		},
		{
			name:         "float32 arithmetic",
			filterString: "float32 * 2 > 64.9",
			expected:     true,
		},
		{
			name:         "float64 arithmetic",
			filterString: "float64 * 2 > 128.9",
			expected:     true,
		},
		{
			name:         "mixed type arithmetic",
			filterString: "float64 > int64 && uint32 > int16",
			expected:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			prog, err := CompileFilterProgram(ds, tc.filterString)
			require.NoError(t, err)

			result, err := Run(prog, data)
			require.NoError(t, err)
			require.Equal(t, tc.expected, result)
		})
	}
}
