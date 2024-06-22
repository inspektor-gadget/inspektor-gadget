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
			acc, err := ds.AddField(fieldName, fieldTypes[i] /*, datasource.WithTags("sorter:"+fieldName)*/)
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
					case api.Kind_Uint32:
						acc.PutUint32(data, valuesIn[i][fi].(uint32))
					case api.Kind_String:
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
				require.Equal(t, array.Len(), len(valuesOut))

				var output [][]any

				for i := 0; i < array.Len(); i++ {
					data := array.Get(i)

					var row []any

					for _, acc := range accessors {
						var ret any
						var err error
						switch acc.Type() {
						case api.Kind_Uint32:
							ret, err = acc.Uint32(data)
						case api.Kind_String:
							ret, err = acc.String(data)
						}
						require.NoError(t, err)
						row = append(row, ret)
					}

					output = append(output, row)
				}

				require.Equal(t, valuesOut, output)

				ds.Dump(array.(datasource.PacketArray), os.Stdout)

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
