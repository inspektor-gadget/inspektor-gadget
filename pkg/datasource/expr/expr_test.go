// Copyright 2024-2025 The Inspektor Gadget authors
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

			res, err := Run(filter, data)
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

			res, err := Run(filter, data)
			require.NoError(t, err)

			require.Equal(t, tc.match, res.(bool), tc.name)
		})
	}
}
