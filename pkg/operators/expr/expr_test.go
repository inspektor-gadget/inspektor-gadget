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
	"context"
	"sync"
	"testing"
	"time"

	"github.com/expr-lang/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
)

func TestExpression(t *testing.T) {
	testCaseData := struct {
		stringValue  string
		int64Value   int64
		float64Value float64
		boolValue    bool
	}{
		stringValue:  "abc",
		int64Value:   123,
		float64Value: 456.0,
		boolValue:    true,
	}
	type testCase struct {
		name         string
		filterString string
		match        bool
		error        bool
	}
	testCases := []testCase{
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
			var ds datasource.DataSource
			var stringField datasource.FieldAccessor
			var int64Field datasource.FieldAccessor
			var float64Field datasource.FieldAccessor
			var boolField datasource.FieldAccessor
			rows := 0
			err := Tester(
				t,
				&expressionOperator{},
				api.ParamValues{
					"operator.expr.expression": "filter:" + tc.filterString,
				},
				func(gadgetCtx operators.GadgetContext) error {
					var err error
					ds, err = gadgetCtx.RegisterDataSource(datasource.TypeSingle, "filter")
					require.NoError(t, err)
					stringField, err = ds.AddField("stringValue", api.Kind_String)
					require.NoError(t, err)
					int64Field, err = ds.AddField("int64Value", api.Kind_Int64)
					require.NoError(t, err)
					float64Field, err = ds.AddField("float64Value", api.Kind_Float64)
					require.NoError(t, err)
					boolField, err = ds.AddField("boolValue", api.Kind_Bool)
					require.NoError(t, err)
					return nil
				},
				func(gadgetCtx operators.GadgetContext) error {
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
					err = ds.EmitAndRelease(data)
					require.NoError(t, err)
					return nil
				},
				func(gadgetCtx operators.GadgetContext) error {
					err := ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
						// t.Logf("received %+v", data)
						rows++
						return nil
					}, Priority+1)
					require.NoError(t, err)
					return nil
				},
			)
			if tc.error {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tc.match {
					assert.Equal(t, rows, 1)
				} else {
					assert.Equal(t, rows, 0)
				}
			}
		})
	}
}

func BenchmarkExpression(b *testing.B) {
	testCaseData := struct {
		stringValue  string
		int64Value   int64
		float64Value float64
		boolValue    bool
	}{
		stringValue:  "abc",
		int64Value:   123,
		float64Value: 456.0,
		boolValue:    true,
	}
	type testCase struct {
		name         string
		filterString string
		match        bool
		error        bool
	}
	testCases := []testCase{
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
		b.Run(tc.name, func(b *testing.B) {
			if tc.error {
				b.Skip()
				return
			}
			ds, err := datasource.New(datasource.TypeSingle, "filter")
			require.NoError(b, err)
			stringField, _ := ds.AddField("stringValue", api.Kind_String)
			int64Field, _ := ds.AddField("int64Value", api.Kind_Int64)
			float64Field, _ := ds.AddField("float64Value", api.Kind_Float64)
			boolField, _ := ds.AddField("boolValue", api.Kind_Bool)

			data, _ := ds.NewPacketSingle()
			stringField.PutString(data, testCaseData.stringValue)
			int64Field.PutInt64(data, testCaseData.int64Value)
			float64Field.PutFloat64(data, testCaseData.float64Value)
			boolField.PutBool(data, testCaseData.boolValue)

			prog, _ := expr.Compile(tc.filterString, expr.Env(&wrap{}), expr.AsBool(), expr.Patch(&dsPatcher{ds: ds}))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				expr.Run(prog, wrap{d: data})
			}
		})
	}
}

func Tester(
	t testing.TB,
	operator operators.DataOperator,
	paramValues api.ParamValues,
	prepare func(operators.GadgetContext) error,
	produce func(operators.GadgetContext) error,
	verify func(operators.GadgetContext) error,
) error {
	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)

	producer := simple.New("producer",
		simple.WithPriority(Priority-1),
		simple.OnInit(prepare),
		simple.OnStart(produce),
	)

	verifier := simple.New("verifier",
		simple.WithPriority(Priority+1),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			defer wg.Done()
			defer cancel()
			return verify(gadgetCtx)
		}),
	)

	gadgetCtx := gadgetcontext.New(ctx, "",
		gadgetcontext.WithDataOperators(operator, producer, verifier),
	)

	return gadgetCtx.Run(paramValues)
}
