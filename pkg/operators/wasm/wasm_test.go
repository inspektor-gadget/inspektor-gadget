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

package wasm_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	orasoci "oras.land/oras-go/v2/content/oci"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/wasm"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

func runGadget(t *testing.T, gadgetCtx *gadgetcontext.GadgetContext, params map[string]string) error {
	runtime := local.New()
	err := runtime.Init(nil)
	if err != nil {
		return err
	}
	t.Cleanup(func() { runtime.Close() })

	if params == nil {
		params = map[string]string{}
	}

	params["operator.oci.verify-image"] = "false"
	return runtime.RunGadget(gadgetCtx, nil, params)
}

func createGadgetCtx(t *testing.T, name string, ops ...operators.DataOperator) *gadgetcontext.GadgetContext {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	t.Cleanup(cancel)

	ociStore, err := orasoci.NewFromTar(ctx, fmt.Sprintf("testdata/%s.tar", name))
	require.NoError(t, err, "creating oci store")

	dataOps := []operators.DataOperator{ocihandler.OciHandler}
	dataOps = append(dataOps, ops...)
	gadgetCtx := gadgetcontext.New(
		ctx,
		fmt.Sprintf("%s:latest", name),
		gadgetcontext.WithDataOperators(dataOps...),
		gadgetcontext.WithOrasReadonlyTarget(ociStore),
	)

	return gadgetCtx
}

func TestWasm(t *testing.T) {
	utilstest.RequireRoot(t)

	t.Parallel()

	tests := []struct {
		name        string
		errExpected bool
	}{
		{"map", false},
		{"mapofmap", false},
		{"badguest", false},
		{"baderrptr", true},
		{"syscall", false},
		{"perf", false},
		{"kallsyms", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			gadgetCtx := createGadgetCtx(t, test.name)
			err := runGadget(t, gadgetCtx, nil)
			if test.errExpected {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestWasmFields(t *testing.T) {
	utilstest.RequireRoot(t)

	t.Parallel()

	type field struct {
		name string
		typ  api.Kind
		acc  datasource.FieldAccessor
		val  any
		tag  string
	}

	// fields added by the wasm module
	fields := []*field{
		{"field_bool", api.Kind_Bool, nil, bool(true), "tag_bool"},
		{"field_int8", api.Kind_Int8, nil, int8(-123), "tag_int8"},
		{"field_int16", api.Kind_Int16, nil, int16(-25647), "tag_int16"},
		{"field_int32", api.Kind_Int32, nil, int32(-535245564), "tag_int32"},
		{"field_int64", api.Kind_Int64, nil, int64(-1234567890), "tag_int64"},
		{"field_uint8", api.Kind_Uint8, nil, uint8(56), "tag_uint8"},
		{"field_uint16", api.Kind_Uint16, nil, uint16(12345), "tag_uint16"},
		{"field_uint32", api.Kind_Uint32, nil, uint32(1234567890), "tag_uint32"},
		{"field_uint64", api.Kind_Uint64, nil, uint64(1234567890123456), "tag_uint64"},
		{"field_float32", api.Kind_Float32, nil, float32(3.14159), "tag_float32"},
		{"field_float64", api.Kind_Float64, nil, float64(3.14159265359), "tag_float64"},
		{"field_string", api.Kind_String, nil, string("Hello, World!"), "tag_string"},
		{"field_bytes", api.Kind_Bytes, nil, []byte{0x01, 0x02, 0x03, 0x04, 0x05}, "tag_bytes"},
	}

	counter := 0

	const opPriority = 50000
	myOperator := simple.New("myHandler",
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			datasources := gadgetCtx.GetDataSources()
			myds, ok := datasources["myds"]
			if !ok {
				return fmt.Errorf("datasource not found")
			}

			for _, f := range fields {
				f.acc = myds.GetField(f.name)
				if f.acc == nil {
					return fmt.Errorf("field %q not found", f.name)
				}

				if f.acc.Type() != f.typ {
					return fmt.Errorf("bad field type: %s vs %s", f.acc.Type(), f.typ)
				}
			}

			myds.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
				counter++

				// Check that fields set by the wasm program are correct
				for _, f := range fields {
					switch f.typ {
					case api.Kind_Int8:
						val, err := f.acc.Int8(data)
						assert.NoError(t, err)
						assert.Equal(t, f.val, val)
						assert.True(t, f.acc.HasAllTagsOf(f.tag))
					case api.Kind_Int16:
						val, err := f.acc.Int16(data)
						assert.NoError(t, err)
						assert.Equal(t, f.val, val)
						assert.True(t, f.acc.HasAllTagsOf(f.tag))
					case api.Kind_Int32:
						val, err := f.acc.Int32(data)
						assert.NoError(t, err)
						assert.Equal(t, f.val, val)
						assert.True(t, f.acc.HasAllTagsOf(f.tag))
					case api.Kind_Int64:
						val, err := f.acc.Int64(data)
						assert.NoError(t, err)
						assert.Equal(t, f.val, val)
						assert.True(t, f.acc.HasAllTagsOf(f.tag))
					case api.Kind_Uint8:
						val, err := f.acc.Uint8(data)
						assert.NoError(t, err)
						assert.Equal(t, f.val, val)
						assert.True(t, f.acc.HasAllTagsOf(f.tag))
					case api.Kind_Uint16:
						val, err := f.acc.Uint16(data)
						assert.NoError(t, err)
						assert.Equal(t, f.val, val)
						assert.True(t, f.acc.HasAllTagsOf(f.tag))
					case api.Kind_Uint32:
						val, err := f.acc.Uint32(data)
						assert.NoError(t, err)
						assert.Equal(t, f.val, val)
						assert.True(t, f.acc.HasAllTagsOf(f.tag))
					case api.Kind_Uint64:
						val, err := f.acc.Uint64(data)
						assert.NoError(t, err)
						assert.Equal(t, f.val, val)
						assert.True(t, f.acc.HasAllTagsOf(f.tag))
					case api.Kind_Float32:
						val, err := f.acc.Float32(data)
						assert.NoError(t, err)
						assert.Equal(t, f.val, val)
						assert.True(t, f.acc.HasAllTagsOf(f.tag))
					case api.Kind_Float64:
						val, err := f.acc.Float64(data)
						assert.NoError(t, err)
						assert.Equal(t, f.val, val)
						assert.True(t, f.acc.HasAllTagsOf(f.tag))
					case api.Kind_String:
						val, err := f.acc.String(data)
						assert.NoError(t, err)
						assert.Equal(t, f.val, val)
						assert.True(t, f.acc.HasAllTagsOf(f.tag))
					case api.Kind_Bytes:
						val, err := f.acc.Bytes(data)
						assert.NoError(t, err)
						assert.Equal(t, f.val, val)
						assert.True(t, f.acc.HasAllTagsOf(f.tag))
					}
				}
				return nil
			}, opPriority)
			return nil
		}),
		simple.OnStart(func(gadgetCtx operators.GadgetContext) error {
			// Emit some packets to the data source
			datasources := gadgetCtx.GetDataSources()
			myds, ok := datasources["myds"]
			require.True(t, ok, "datasource not found")

			packet, err := myds.NewPacketSingle()
			require.NoError(t, err, "creating packet")

			err = myds.EmitAndRelease(packet)
			require.NoError(t, err, "emitting packet")

			return nil
		}),
	)

	gadgetCtx := createGadgetCtx(t, "fields", myOperator)

	// Register data source that will be used by the wasm program to add fields
	ds, err := gadgetCtx.RegisterDataSource(datasource.TypeSingle, "myds")
	require.NoError(t, err, "registering datasource")

	hostF, err := ds.AddField("host_field", api.Kind_String)
	hostF.AddTags("host_tag")
	require.NoError(t, err, "adding field")

	fields = append(fields, &field{
		name: "host_field",
		typ:  api.Kind_String,
		acc:  hostF,
		val:  "LOCALHOST",
		tag:  "host_tag",
	},
	)

	err = runGadget(t, gadgetCtx, nil)
	require.NoError(t, err, "running gadget")

	require.Equal(t, counter, 1)
}

func TestWasmDataArray(t *testing.T) {
	utilstest.RequireRoot(t)

	t.Parallel()

	counter := 0

	const opPriority = 50000
	myOperator := simple.New("myHandler",
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			datasources := gadgetCtx.GetDataSources()
			myds, ok := datasources["myds"]
			require.True(t, ok, "datasource not found")

			acc := myds.GetField("foo")
			myds.SubscribeArray(func(source datasource.DataSource, dataArray datasource.DataArray) error {
				counter++

				// 10 we add here + 5 added in wasm
				require.Equal(t, 15, dataArray.Len())

				for i := 0; i < dataArray.Len(); i++ {
					data := dataArray.Get(i)
					val, err := acc.Uint32(data)
					require.NoError(t, err)

					require.Equal(t, uint32(424143*i), val)
				}

				return nil
			}, opPriority)
			return nil
		}),
		simple.OnStart(func(gadgetCtx operators.GadgetContext) error {
			// Emit some packets to the data source
			datasources := gadgetCtx.GetDataSources()
			myds, ok := datasources["myds"]
			require.True(t, ok, "datasource not found")

			packet, err := myds.NewPacketArray()
			require.NoError(t, err, "creating packet")

			acc := myds.GetField("foo")

			for i := 0; i < 10; i++ {
				data := packet.New()
				err = acc.PutUint32(data, uint32(424143))
				require.NoError(t, err, "putting data")

				packet.Append(data)
			}

			err = myds.EmitAndRelease(packet)
			require.NoError(t, err, "emitting data")

			return nil
		}),
	)

	gadgetCtx := createGadgetCtx(t, "dataarray", myOperator)

	// Register data source that will be used by the wasm program to add fields
	ds, err := gadgetCtx.RegisterDataSource(datasource.TypeArray, "myds")
	require.NoError(t, err, "registering datasource")

	_, err = ds.AddField("foo", api.Kind_Uint32)
	require.NoError(t, err)

	err = runGadget(t, gadgetCtx, nil)
	require.NoError(t, err, "running gadget")

	require.Equal(t, counter, 1)
}

func TestWasmDataEmit(t *testing.T) {
	utilstest.RequireRoot(t)

	t.Parallel()

	counter := 0

	const opPriority = 50000
	myOperator := simple.New("myHandler",
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			// Verify the new data source
			datasources := gadgetCtx.GetDataSources()
			ds, ok := datasources["new_ds"]
			require.True(t, ok, "datasource not found")

			acc := ds.GetField("bar")
			ds.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
				counter++

				// Even value 2 multiplied by 5 = 10
				val, err := acc.Uint32(data)
				require.NoError(t, err)
				require.Equal(t, uint32(10), val)

				return nil
			}, opPriority)
			return nil
		}),
		simple.OnStart(func(gadgetCtx operators.GadgetContext) error {
			// Emit some packets to the old data source
			datasources := gadgetCtx.GetDataSources()
			ds, ok := datasources["old_ds"]
			require.True(t, ok, "datasource not found")

			packet, err := ds.NewPacketArray()
			require.NoError(t, err, "creating packet")

			acc := ds.GetField("foo")

			// Emitting numbers 1 and 2
			for i := 1; i < 3; i++ {
				data := packet.New()
				err = acc.PutUint32(data, uint32(i))
				require.NoError(t, err, "putting data")

				packet.Append(data)
			}

			err = ds.EmitAndRelease(packet)
			require.NoError(t, err, "emitting data")

			return nil
		}),
	)

	gadgetCtx := createGadgetCtx(t, "dataemit", myOperator)

	// Register data source that will be used by the wasm program to add fields
	ds, err := gadgetCtx.RegisterDataSource(datasource.TypeArray, "old_ds")
	require.NoError(t, err, "registering datasource")

	_, err = ds.AddField("foo", api.Kind_Uint32)
	require.NoError(t, err)

	err = runGadget(t, gadgetCtx, nil)
	require.NoError(t, err, "running gadget")

	require.Equal(t, counter, 1) // as only 1 of the two packets emitted by the `old_ds` will be passed on to the `new_ds`
}

func TestWasmParams(t *testing.T) {
	utilstest.RequireRoot(t)

	t.Parallel()

	myOperator := simple.New("myHandler",
		simple.OnStart(func(gadgetCtx operators.GadgetContext) error {
			params := gadgetCtx.Params()
			found := false
			for _, p := range params {
				if p.Key == "param-key" {
					require.Equal(t, "param-description", p.Description)
					require.Equal(t, "param-default-value", p.DefaultValue)
					require.Equal(t, "param-type-hint", p.TypeHint)
					require.Equal(t, "param-title", p.Title)
					require.Equal(t, "param-alias", p.Alias)
					require.True(t, p.IsMandatory)

					found = true
					break
				}
			}

			require.True(t, found, "param not found")
			return nil
		}),
	)

	gadgetCtx := createGadgetCtx(t, "params", myOperator)
	params := map[string]string{
		"operator.oci.wasm.param-key": "param-value",
	}

	err := runGadget(t, gadgetCtx, params)
	require.NoError(t, err, "running gadget")
}

func TestConfig(t *testing.T) {
	utilstest.RequireRoot(t)

	t.Parallel()

	gadgetCtx := createGadgetCtx(t, "config")
	err := runGadget(t, gadgetCtx, nil)
	require.NoError(t, err, "running gadget")

	cfg, ok := gadgetCtx.GetVar("config")
	require.True(t, ok, "missing configuration")
	v, ok := cfg.(*viper.Viper)
	require.True(t, ok, "invalid configuration format")

	require.Equal(t, "myvalue", v.GetString("foo.bar.zas"))
}

func TestFiltering(t *testing.T) {
	gadgetCtx := createGadgetCtx(t, "filtering")

	mntNsMap := utilstest.CreateMntNsFilterMap(t, 777)
	gadgetCtx.SetVar(gadgets.MntNsFilterMapName, mntNsMap)

	err := runGadget(t, gadgetCtx, nil)
	require.NoError(t, err, "running gadget")
}
