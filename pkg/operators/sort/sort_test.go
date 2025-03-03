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

package sort

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

func Tester(
	t *testing.T,
	operator operators.DataOperator,
	paramValues api.ParamValues,
	prepare func(operators.GadgetContext) error,
	produce func(operators.GadgetContext) error,
	verify func(operators.GadgetContext) error,
) {
	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)

	producer := simple.New("producer",
		simple.WithPriority(Priority-1),
		simple.OnInit(prepare),
		simple.OnStart(produce),
		simple.OnStop(func(gadgetCtx operators.GadgetContext) error {
			// Remove me once OnStop in SimpleOperator is fixed
			return nil
		}),
	)

	verifier := simple.New("verifier",
		simple.WithPriority(Priority+1),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			defer wg.Done()
			defer cancel()
			return verify(gadgetCtx)
		}),
	)

	gadgetCtx := gadgetcontext.New(ctx, "", gadgetcontext.WithDataOperators(operator, producer, verifier))

	err := gadgetCtx.Run(paramValues)
	assert.NoError(t, err)
}

func SortTester(
	t *testing.T,
	fieldTypes []api.Kind,
	fieldNames []string,
	valuesIn [][]any,
	valuesOut [][]any,
	param string,
) {
	var accessors []datasource.FieldAccessor

	prepare := func(gadgetCtx operators.GadgetContext) error {
		ds, err := gadgetCtx.RegisterDataSource(datasource.TypeArray, "foo")
		assert.NoError(t, err)

		for i, fieldName := range fieldNames {
			acc, err := ds.AddField(fieldName, fieldTypes[i])
			assert.NoError(t, err)
			accessors = append(accessors, acc)
		}
		return nil
	}

	produce := func(gadgetCtx operators.GadgetContext) error {
		for _, ds := range gadgetCtx.GetDataSources() {
			if ds.Type() != datasource.TypeArray {
				continue
			}

			arr, _ := ds.NewPacketArray()
			for i := 0; i < len(valuesIn); i++ {
				data := arr.New()
				for fi, acc := range accessors {
					switch acc.Type() {
					case api.Kind_Int8:
						acc.PutInt8(data, valuesIn[i][fi].(int8))
					case api.Kind_Int16:
						acc.PutInt16(data, valuesIn[i][fi].(int16))
					case api.Kind_Int32:
						acc.PutInt32(data, valuesIn[i][fi].(int32))
					case api.Kind_Int64:
						acc.PutInt64(data, valuesIn[i][fi].(int64))
					case api.Kind_Uint8:
						acc.PutUint8(data, valuesIn[i][fi].(uint8))
					case api.Kind_Uint16:
						acc.PutUint16(data, valuesIn[i][fi].(uint16))
					case api.Kind_Uint32:
						acc.PutUint32(data, valuesIn[i][fi].(uint32))
					case api.Kind_Uint64:
						acc.PutUint64(data, valuesIn[i][fi].(uint64))
					case api.Kind_Float32:
						acc.PutFloat32(data, valuesIn[i][fi].(float32))
					case api.Kind_Float64:
						acc.PutFloat64(data, valuesIn[i][fi].(float64))
					case api.Kind_String:
						acc.PutString(data, valuesIn[i][fi].(string))
					case api.Kind_CString:
						acc.PutString(data, valuesIn[i][fi].(string))
					}
				}

				arr.Append(data)
			}

			err := ds.EmitAndRelease(arr)
			assert.NoError(t, err)
		}
		return nil
	}

	verify := func(gadgetCtx operators.GadgetContext) error {
		for _, s := range gadgetCtx.GetDataSources() {
			if s.Type() != datasource.TypeArray {
				continue
			}
			s.SubscribeArray(func(ds datasource.DataSource, array datasource.DataArray) error {
				// Fix for empty array test - initialize an empty slice instead of nil
				output := make([][]any, 0)

				if array != nil {
					// Handle case where array length might be 0 but array is not nil
					require.Equal(t, array.Len(), len(valuesOut))

					for i := 0; i < array.Len(); i++ {
						data := array.Get(i)

						var row []any

						for _, acc := range accessors {
							var ret any
							var err error
							switch acc.Type() {
							case api.Kind_Int8:
								ret, err = acc.Int8(data)
							case api.Kind_Int16:
								ret, err = acc.Int16(data)
							case api.Kind_Int32:
								ret, err = acc.Int32(data)
							case api.Kind_Int64:
								ret, err = acc.Int64(data)
							case api.Kind_Uint8:
								ret, err = acc.Uint8(data)
							case api.Kind_Uint16:
								ret, err = acc.Uint16(data)
							case api.Kind_Uint32:
								ret, err = acc.Uint32(data)
							case api.Kind_Uint64:
								ret, err = acc.Uint64(data)
							case api.Kind_Float32:
								ret, err = acc.Float32(data)
							case api.Kind_Float64:
								ret, err = acc.Float64(data)
							case api.Kind_String:
								ret, err = acc.String(data)
							case api.Kind_CString:
								ret, err = acc.String(data)
							}
							require.NoError(t, err)
							row = append(row, ret)
						}

						output = append(output, row)
					}
				}

				require.Equal(t, valuesOut, output)

				if array != nil {
					ds.Dump(array.(datasource.PacketArray), os.Stdout)
				}

				return nil
			}, Priority+1)
		}
		return nil
	}

	Tester(
		t,
		Operator,
		api.ParamValues{
			"operator.sort.sort": param,
		},
		prepare,
		produce,
		verify,
	)
}

// Existing tests
func TestNumbers(t *testing.T) {
	SortTester(
		t,
		[]api.Kind{api.Kind_Uint32},
		[]string{"number"},
		[][]any{{uint32(5)}, {uint32(4)}, {uint32(3)}, {uint32(2)}, {uint32(1)}},
		[][]any{{uint32(1)}, {uint32(2)}, {uint32(3)}, {uint32(4)}, {uint32(5)}},
		"number",
	)
}

func TestNumbersDesc(t *testing.T) {
	SortTester(
		t,
		[]api.Kind{api.Kind_Uint32},
		[]string{"number"},
		[][]any{{uint32(1)}, {uint32(2)}, {uint32(3)}, {uint32(4)}, {uint32(5)}},
		[][]any{{uint32(5)}, {uint32(4)}, {uint32(3)}, {uint32(2)}, {uint32(1)}},
		"-number",
	)
}

func TestStrings(t *testing.T) {
	SortTester(
		t,
		[]api.Kind{api.Kind_String},
		[]string{"string"},
		[][]any{{"mno"}, {"ghi"}, {"abc"}, {"def"}, {"jkl"}},
		[][]any{{"abc"}, {"def"}, {"ghi"}, {"jkl"}, {"mno"}},
		"string",
	)
}

func TestMultiple(t *testing.T) {
	SortTester(
		t,
		[]api.Kind{api.Kind_String, api.Kind_Uint32},
		[]string{"string", "number"},
		[][]any{
			{"mno", uint32(0x56)},
			{"mno", uint32(0x45)},
			{"abc", uint32(0x0)},
			{"abc", uint32(0x5)},
			{"jkl", uint32(0x2)},
		},
		[][]any{
			{"abc", uint32(0x0)},
			{"abc", uint32(0x5)},
			{"jkl", uint32(0x2)},
			{"mno", uint32(0x45)},
			{"mno", uint32(0x56)},
		},
		"string,number",
	)
}

func TestInt8(t *testing.T) {
	SortTester(
		t,
		[]api.Kind{api.Kind_Int8},
		[]string{"number"},
		[][]any{{int8(5)}, {int8(-4)}, {int8(3)}, {int8(-2)}, {int8(1)}},
		[][]any{{int8(-4)}, {int8(-2)}, {int8(1)}, {int8(3)}, {int8(5)}},
		"number",
	)
}

func TestInt16(t *testing.T) {
	SortTester(
		t,
		[]api.Kind{api.Kind_Int16},
		[]string{"number"},
		[][]any{{int16(500)}, {int16(-400)}, {int16(300)}, {int16(-200)}, {int16(100)}},
		[][]any{{int16(-400)}, {int16(-200)}, {int16(100)}, {int16(300)}, {int16(500)}},
		"number",
	)
}

func TestInt32(t *testing.T) {
	SortTester(
		t,
		[]api.Kind{api.Kind_Int32},
		[]string{"number"},
		[][]any{{int32(50000)}, {int32(-40000)}, {int32(30000)}, {int32(-20000)}, {int32(10000)}},
		[][]any{{int32(-40000)}, {int32(-20000)}, {int32(10000)}, {int32(30000)}, {int32(50000)}},
		"number",
	)
}

func TestInt64(t *testing.T) {
	SortTester(
		t,
		[]api.Kind{api.Kind_Int64},
		[]string{"number"},
		[][]any{{int64(5000000000)}, {int64(-4000000000)}, {int64(3000000000)}, {int64(-2000000000)}, {int64(1000000000)}},
		[][]any{{int64(-4000000000)}, {int64(-2000000000)}, {int64(1000000000)}, {int64(3000000000)}, {int64(5000000000)}},
		"number",
	)
}

func TestUint8(t *testing.T) {
	SortTester(
		t,
		[]api.Kind{api.Kind_Uint8},
		[]string{"number"},
		[][]any{{uint8(255)}, {uint8(200)}, {uint8(150)}, {uint8(100)}, {uint8(50)}},
		[][]any{{uint8(50)}, {uint8(100)}, {uint8(150)}, {uint8(200)}, {uint8(255)}},
		"number",
	)
}

func TestUint16(t *testing.T) {
	SortTester(
		t,
		[]api.Kind{api.Kind_Uint16},
		[]string{"number"},
		[][]any{{uint16(65000)}, {uint16(50000)}, {uint16(30000)}, {uint16(20000)}, {uint16(10000)}},
		[][]any{{uint16(10000)}, {uint16(20000)}, {uint16(30000)}, {uint16(50000)}, {uint16(65000)}},
		"number",
	)
}

func TestUint64(t *testing.T) {
	SortTester(
		t,
		[]api.Kind{api.Kind_Uint64},
		[]string{"number"},
		[][]any{{uint64(18446744073709551610)}, {uint64(9000000000000000000)}, {uint64(5000000000000000000)}, {uint64(1000000000000000000)}, {uint64(500000000000000000)}},
		[][]any{{uint64(500000000000000000)}, {uint64(1000000000000000000)}, {uint64(5000000000000000000)}, {uint64(9000000000000000000)}, {uint64(18446744073709551610)}},
		"number",
	)
}

func TestFloat32(t *testing.T) {
	SortTester(
		t,
		[]api.Kind{api.Kind_Float32},
		[]string{"number"},
		[][]any{{float32(5.5)}, {float32(-4.4)}, {float32(3.3)}, {float32(-2.2)}, {float32(1.1)}},
		[][]any{{float32(-4.4)}, {float32(-2.2)}, {float32(1.1)}, {float32(3.3)}, {float32(5.5)}},
		"number",
	)
}

func TestFloat64(t *testing.T) {
	SortTester(
		t,
		[]api.Kind{api.Kind_Float64},
		[]string{"number"},
		[][]any{{float64(5.5555)}, {float64(-4.4444)}, {float64(3.3333)}, {float64(-2.2222)}, {float64(1.1111)}},
		[][]any{{float64(-4.4444)}, {float64(-2.2222)}, {float64(1.1111)}, {float64(3.3333)}, {float64(5.5555)}},
		"number",
	)
}

func TestCString(t *testing.T) {
	SortTester(
		t,
		[]api.Kind{api.Kind_CString},
		[]string{"string"},
		[][]any{{"xyz"}, {"pqr"}, {"abc"}, {"hij"}, {"def"}},
		[][]any{{"abc"}, {"def"}, {"hij"}, {"pqr"}, {"xyz"}},
		"string",
	)
}

func TestEmptyArray(t *testing.T) {
	SortTester(
		t,
		[]api.Kind{api.Kind_Uint32},
		[]string{"number"},
		[][]any{},
		[][]any{}, // Empty slice, not nil
		"number",
	)
}

func TestMixedOrdering(t *testing.T) {
	SortTester(
		t,
		[]api.Kind{api.Kind_String, api.Kind_Uint32},
		[]string{"string", "number"},
		[][]any{
			{"abc", uint32(0x0)},
			{"abc", uint32(0x5)},
			{"jkl", uint32(0x2)},
			{"mno", uint32(0x45)},
			{"mno", uint32(0x56)},
		},
		[][]any{
			{"abc", uint32(0x5)},
			{"abc", uint32(0x0)},
			{"jkl", uint32(0x2)},
			{"mno", uint32(0x56)},
			{"mno", uint32(0x45)},
		},
		"string,-number",
	)
}

func TestErrorCases(t *testing.T) {
	t.Run("InvalidFieldName", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
		defer cancel()

		prepare := func(gadgetCtx operators.GadgetContext) error {
			ds, err := gadgetCtx.RegisterDataSource(datasource.TypeArray, "foo")
			assert.NoError(t, err)
			_, err = ds.AddField("number", api.Kind_Uint32)
			assert.NoError(t, err)
			return nil
		}

		producer := simple.New("producer",
			simple.WithPriority(Priority-1),
			simple.OnInit(prepare),
		)

		gadgetCtx := gadgetcontext.New(ctx, "", gadgetcontext.WithDataOperators(Operator, producer))

		err := gadgetCtx.Run(api.ParamValues{
			"operator.sort.sort": "nonexistent_field",
		})

		assert.Error(t, err)
	})

	t.Run("UnsortableFieldType", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
		defer cancel()

		prepare := func(gadgetCtx operators.GadgetContext) error {
			ds, err := gadgetCtx.RegisterDataSource(datasource.TypeArray, "foo")
			assert.NoError(t, err)
			_, err = ds.AddField("complex", api.Kind_Bool)
			assert.NoError(t, err)
			return nil
		}

		producer := simple.New("producer",
			simple.WithPriority(Priority-1),
			simple.OnInit(prepare),
		)

		gadgetCtx := gadgetcontext.New(ctx, "", gadgetcontext.WithDataOperators(Operator, producer))

		err := gadgetCtx.Run(api.ParamValues{
			"operator.sort.sort": "complex",
		})

		assert.Error(t, err)
	})

	t.Run("MixingSortingRules", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
		defer cancel()

		prepare := func(gadgetCtx operators.GadgetContext) error {
			ds1, err := gadgetCtx.RegisterDataSource(datasource.TypeArray, "foo")
			assert.NoError(t, err)
			_, err = ds1.AddField("number", api.Kind_Uint32)
			assert.NoError(t, err)

			ds2, err := gadgetCtx.RegisterDataSource(datasource.TypeArray, "bar")
			assert.NoError(t, err)
			_, err = ds2.AddField("string", api.Kind_String)
			assert.NoError(t, err)

			return nil
		}

		producer := simple.New("producer",
			simple.WithPriority(Priority-1),
			simple.OnInit(prepare),
		)

		gadgetCtx := gadgetcontext.New(ctx, "", gadgetcontext.WithDataOperators(Operator, producer))

		err := gadgetCtx.Run(api.ParamValues{
			"operator.sort.sort": "number;bar:string",
		})

		assert.Error(t, err)
	})

	t.Run("NonArrayDataSource", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
		defer cancel()

		prepare := func(gadgetCtx operators.GadgetContext) error {
			ds, err := gadgetCtx.RegisterDataSource(datasource.TypeSingle, "foo")
			assert.NoError(t, err)
			_, err = ds.AddField("number", api.Kind_Uint32)
			assert.NoError(t, err)
			return nil
		}

		producer := simple.New("producer",
			simple.WithPriority(Priority-1),
			simple.OnInit(prepare),
		)

		gadgetCtx := gadgetcontext.New(ctx, "", gadgetcontext.WithDataOperators(Operator, producer))

		err := gadgetCtx.Run(api.ParamValues{
			"operator.sort.sort": "number",
		})

		assert.NoError(t, err)
	})
}

func TestOperatorDirectly(t *testing.T) {
	t.Run("TestInit", func(t *testing.T) {
		op := &sortOperator{}
		err := op.Init(&params.Params{})
		assert.NoError(t, err)
		assert.Equal(t, "sort", op.Name())
		assert.Equal(t, Priority, op.Priority())
	})

	t.Run("TestGlobalParams", func(t *testing.T) {
		op := &sortOperator{}
		params := op.GlobalParams()
		assert.Nil(t, params)
	})

	t.Run("TestInstanceParams", func(t *testing.T) {
		op := &sortOperator{}
		params := op.InstanceParams()
		assert.NotNil(t, params)
		assert.Equal(t, 1, len(params))
		assert.Equal(t, ParamSortBy, params[0].Key)
	})
}

func TestMultipleDataSources(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)

	prepare := func(gadgetCtx operators.GadgetContext) error {
		ds1, err := gadgetCtx.RegisterDataSource(datasource.TypeArray, "foo")
		assert.NoError(t, err)
		_, err = ds1.AddField("number", api.Kind_Uint32)
		assert.NoError(t, err)

		ds2, err := gadgetCtx.RegisterDataSource(datasource.TypeArray, "bar")
		assert.NoError(t, err)
		_, err = ds2.AddField("string", api.Kind_String)
		assert.NoError(t, err)

		return nil
	}

	produce := func(gadgetCtx operators.GadgetContext) error {
		for _, ds := range gadgetCtx.GetDataSources() {
			if ds.Type() != datasource.TypeArray {
				continue
			}

			arr, _ := ds.NewPacketArray()

			if ds.Name() == "foo" {
				values := []uint32{5, 4, 3, 2, 1}

				for _, val := range values {
					data := arr.New()
					numberAcc := ds.GetField("number")
					if numberAcc != nil {
						numberAcc.PutUint32(data, val)
					}
					arr.Append(data)
				}
			} else if ds.Name() == "bar" {
				values := []string{"xyz", "pqr", "abc", "hij", "def"}

				for _, val := range values {
					data := arr.New()
					stringAcc := ds.GetField("string")
					if stringAcc != nil {
						stringAcc.PutString(data, val)
					}
					arr.Append(data)
				}
			}

			err := ds.EmitAndRelease(arr)
			assert.NoError(t, err)
		}
		return nil
	}

	verify := func(gadgetCtx operators.GadgetContext) error {
		defer wg.Done()
		defer cancel()

		for _, s := range gadgetCtx.GetDataSources() {
			if s.Type() != datasource.TypeArray {
				continue
			}

			if s.Name() == "foo" {
				s.SubscribeArray(func(ds datasource.DataSource, array datasource.DataArray) error {
					expected := []uint32{1, 2, 3, 4, 5}
					require.Equal(t, len(expected), array.Len())

					numberAcc := ds.GetField("number")
					require.NotNil(t, numberAcc)

					for i := 0; i < array.Len(); i++ {
						data := array.Get(i)
						val, err := numberAcc.Uint32(data)
						require.NoError(t, err)
						require.Equal(t, expected[i], val)
					}
					return nil
				}, Priority+1)
			} else if s.Name() == "bar" {
				s.SubscribeArray(func(ds datasource.DataSource, array datasource.DataArray) error {
					expected := []string{"xyz", "pqr", "abc", "hij", "def"}
					require.Equal(t, len(expected), array.Len())

					stringAcc := ds.GetField("string")
					require.NotNil(t, stringAcc)

					for i := 0; i < array.Len(); i++ {
						data := array.Get(i)
						val, err := stringAcc.String(data)
						require.NoError(t, err)
						require.Equal(t, expected[i], val)
					}
					return nil
				}, Priority+1)
			}
		}
		return nil
	}

	producer := simple.New("producer",
		simple.WithPriority(Priority-1),
		simple.OnInit(prepare),
		simple.OnStart(produce),
	)

	verifier := simple.New("verifier",
		simple.WithPriority(Priority+1),
		simple.OnInit(verify),
	)

	gadgetCtx := gadgetcontext.New(ctx, "", gadgetcontext.WithDataOperators(Operator, producer, verifier))

	err := gadgetCtx.Run(api.ParamValues{
		"operator.sort.sort": "foo:number",
	})
	assert.NoError(t, err)

	wg.Wait()
}

func TestNoSort(t *testing.T) {
	SortTester(
		t,
		[]api.Kind{api.Kind_Uint32},
		[]string{"number"},
		[][]any{{uint32(5)}, {uint32(4)}, {uint32(3)}, {uint32(2)}, {uint32(1)}},
		[][]any{{uint32(5)}, {uint32(4)}, {uint32(3)}, {uint32(2)}, {uint32(1)}},
		"",
	)
}
