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

package wasm

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	orasoci "oras.land/oras-go/v2/content/oci"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
)

func initDataHandleTest(t *testing.T, image string, datasourceName string) (datasource.DataSource, datasource.FieldAccessor, *wasmOperatorInstance) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	t.Cleanup(cancel)

	ociStore, err := orasoci.NewFromTar(ctx, fmt.Sprintf("testdata/%s.tar", image))
	require.NoError(t, err, "creating oci store")

	gadgetCtx := gadgetcontext.New(
		ctx,
		fmt.Sprintf("%s:latest", image),
		gadgetcontext.WithDataOperators(ocihandler.OciHandler),
		gadgetcontext.WithOrasReadonlyTarget(ociStore),
	)

	// Register data source that will be used by the wasm program to add fields
	ds, err := gadgetCtx.RegisterDataSource(datasource.TypeArray, datasourceName)
	require.NoError(t, err, "registering datasource")

	fooAcc, err := ds.AddField("foo", api.Kind_Uint32)
	require.NoError(t, err)

	// Start WASM
	h := ocihandler.OciHandler
	instance, err := h.InstantiateDataOperator(gadgetCtx, nil)
	require.NoError(t, err, "instantiating data operator")
	require.NotNil(t, instance, "instance is nil")
	err = instance.Start(gadgetCtx)
	require.NoError(t, err, "starting instance")

	t.Cleanup(func() {
		instance.Stop(gadgetCtx)
	})

	wasmInstanceAny, found := gadgetCtx.GetVar(wasmInstanceTestingVarName)
	require.True(t, found, "wasm instance not found")
	require.NotNil(t, wasmInstanceAny, "wasm instance is nil")
	wasmInstance, ok := wasmInstanceAny.(*wasmOperatorInstance)
	require.True(t, ok, "wasm instance is not a *wasmOperatorInstance")

	return ds, fooAcc, wasmInstance
}

func TestHandleEmitAndRelease(t *testing.T) {
	t.Parallel()
	ds, fooAcc, wasmInstance := initDataHandleTest(t, "dataemit", "old_ds")

	prevHandleLen := len(wasmInstance.handleMap)

	// Create new packet and emit it
	newArrPkt, err := ds.NewPacketArray()
	require.NoError(t, err, "creating new array packet")
	newData := newArrPkt.New()
	require.NotNil(t, newData, "new data is nil")
	err = fooAcc.PutUint32(newData, 2)
	require.NoError(t, err, "putting uint32")
	newArrPkt.Append(newData)
	ds.EmitAndRelease(newArrPkt)

	// Check if the handle map has stayed the same after going through the wasm program
	require.Equal(t, prevHandleLen, len(wasmInstance.handleMap), "handle map length changed")
}

func TestHandleDataArrayGet(t *testing.T) {
	t.Parallel()
	ds, fooAcc, wasmInstance := initDataHandleTest(t, "dataarray", "myds")

	prevHandleLen := len(wasmInstance.handleMap)

	// Create new packet and emit it
	newArrPkt, err := ds.NewPacketArray()
	require.NoError(t, err, "creating new array packet")
	newData := newArrPkt.New()
	require.NotNil(t, newData, "new data is nil")
	for i := 0; i < 10; i++ {
		err = fooAcc.PutUint32(newData, uint32(i))
		require.NoError(t, err, "putting uint32")
		newArrPkt.Append(newData)
	}
	ds.EmitAndRelease(newArrPkt)

	// Check if the handle map has stayed the same after going through the wasm program
	require.Equal(t, prevHandleLen, len(wasmInstance.handleMap), "handle map length changed")
}

func TestHandleMapGet(t *testing.T) {
	utilstest.RequireRoot(t)
	t.Parallel()
	_, _, wasmInstance := initDataHandleTest(t, "map", "a")

	// Check if the eBPF program released its handle after the init
	require.Equal(t, 0, len(wasmInstance.handleMap), "handle map length is not 0")
}
