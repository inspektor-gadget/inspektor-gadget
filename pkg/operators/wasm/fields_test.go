/*
Copyright 2024 The Inspektor Gadget authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	p://www.apache.org/licenses/LICENSE-2.0
*/
package wasm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	wapi "github.com/tetratelabs/wazero/api"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gapi "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

func TestFieldGetBuffer_AcceptsCString(t *testing.T) {
	t.Parallel()

	// Override the package-level hook so we don't need a real wazero Module/Memory.
	orig := writeToDstBufferFn
	defer func() { writeToDstBufferFn = orig }()

	var captured []byte
	writeToDstBufferFn = func(i *wasmOperatorInstance, src []byte, dst uint64) error {
		// copy to avoid referencing internal buffers
		captured = append([]byte(nil), src...)
		return nil
	}

	ds, err := datasource.New(datasource.TypeSingle, "event")
	require.NoError(t, err)

	acc, err := ds.AddField("f1", gapi.Kind_CString)
	require.NoError(t, err)

	d, err := ds.NewPacketSingle()
	require.NoError(t, err)

	input := "/dev/null"
	require.NoError(t, acc.PutString(d, input))

	inst := &wasmOperatorInstance{
		handleMap: map[uint32]any{},
	}

	fh := inst.addHandle(acc)
	dh := inst.addHandle(d)

	stack := []uint64{
		wapi.EncodeU32(fh),
		wapi.EncodeU32(dh),
		wapi.EncodeU32(uint32(gapi.Kind_CString)),
		0, // destination buffer (unused by our stub)
	}

	inst.fieldGetBuffer(context.Background(), nil, stack)

	// The result (number of bytes written) is stored in stack[0]
	require.Equal(t, uint64(len(captured)), stack[0])
	require.Equal(t, []byte(input), captured)
}
