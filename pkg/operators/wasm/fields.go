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

	"github.com/tetratelabs/wazero"
	wapi "github.com/tetratelabs/wazero/api"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

func (i *wasmOperatorInstance) addFieldFuncs(env wazero.HostModuleBuilder) {
	exportFunction(env, "fieldGet", i.fieldGet,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // Accessor
			wapi.ValueTypeI32, // Data
			wapi.ValueTypeI32, // Kind
		},
		[]wapi.ValueType{wapi.ValueTypeI64}, // Value
	)

	exportFunction(env, "fieldSet", i.fieldSet,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // Accessor
			wapi.ValueTypeI32, // Data
			wapi.ValueTypeI32, // Kind
			wapi.ValueTypeI64, // Value
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Error
	)
}

// fieldGet returns the field's value.
// Params:
// - stack[0]: Field handle
// - stack[1]: Data handle
// - stack[2]: Kind
// Return value:
// - Uint64 representation of the value of the field, depending on the type
// requested, or a pointer, 0 on error.
// TODO: error handling is still TBD as there not a way to differentiate between
// a field with value 0 and an error.
func (i *wasmOperatorInstance) fieldGet(ctx context.Context, m wapi.Module, stack []uint64) {
	fieldHandle := wapi.DecodeU32(stack[0])
	dataHandle := wapi.DecodeU32(stack[1])
	fieldKind := api.Kind(wapi.DecodeU32(stack[2]))

	field, ok := getHandle[datasource.FieldAccessor](i, fieldHandle)
	if !ok {
		stack[0] = 0
		return
	}
	data, ok := getHandle[datasource.Data](i, dataHandle)
	if !ok {
		stack[0] = 0
		return
	}

	handleBytes := func(buf []byte) uint64 {
		res, err := i.guestMalloc.Call(ctx, uint64(len(buf)))
		if err != nil {
			i.logger.Warnf("malloc failed: %v", err)
			stack[0] = 0
			return 0

		}

		if !m.Memory().Write(uint32(res[0]), buf) {
			i.logger.Warnf("out of memory write")
			stack[0] = 0
			return 0
		}

		return uint64(len(buf))<<32 | uint64(res[0])
	}

	var val uint64
	var err error

	switch fieldKind {
	case api.Kind_Bool:
		var ret bool
		ret, err = field.Bool(data)
		if ret {
			val = 1
		} else {
			val = 0
		}
	case api.Kind_Int8:
		var ret int8
		ret, err = field.Int8(data)
		val = uint64(ret)
	case api.Kind_Int16:
		var ret int16
		ret, err = field.Int16(data)
		val = uint64(ret)
	case api.Kind_Int32:
		var ret int32
		ret, err = field.Int32(data)
		val = uint64(ret)
	case api.Kind_Int64:
		var ret int64
		ret, err = field.Int64(data)
		val = uint64(ret)
	case api.Kind_Uint8:
		var ret uint8
		ret, err = field.Uint8(data)
		val = uint64(ret)
	case api.Kind_Uint16:
		var ret uint16
		ret, err = field.Uint16(data)
		val = uint64(ret)
	case api.Kind_Uint32:
		var ret uint32
		ret, err = field.Uint32(data)
		val = uint64(ret)
	case api.Kind_Uint64:
		val, err = field.Uint64(data)
	// The guest has to pass floats using the IEEE 754 binary representation
	case api.Kind_Float32:
		var ret uint32
		ret, err = field.Uint32(data)
		val = uint64(ret)
	case api.Kind_Float64:
		val, err = field.Uint64(data)
	// These are a bit special as they don't fit in the return value, so we have to
	// allocate an array in the guest memory and return a pointer to it.
	case api.Kind_String:
		str, err := field.String(data)
		if err == nil {
			val = handleBytes([]byte(str))
		}
	case api.Kind_Bytes:
		bytes, err := field.Bytes(data)
		if err == nil {
			val = handleBytes(bytes)
		}
	default:
		i.logger.Warnf("unknown field kind: %d", stack[2])
		stack[0] = 0
		return
	}

	if err != nil {
		i.logger.Warnf("fieldGet for field %q failed: %v", field.Name(), err)
		stack[0] = 0
		return
	}

	stack[0] = val
}

// fieldSet sets the field's value
// Params:
// - stack[0]: Field handle
// - stack[1]: Data handle
// - stack[2]: Kind
// - stack[3]: Value to store
// Return value:
// - 0 on success, 1 on error
func (i *wasmOperatorInstance) fieldSet(ctx context.Context, m wapi.Module, stack []uint64) {
	fieldHandle := wapi.DecodeU32(stack[0])
	dataHandle := wapi.DecodeU32(stack[1])
	fieldKind := api.Kind(wapi.DecodeU32(stack[2]))
	value := stack[3]

	field, ok := getHandle[datasource.FieldAccessor](i, fieldHandle)
	if !ok {
		stack[0] = 1
		return
	}
	data, ok := getHandle[datasource.Data](i, dataHandle)
	if !ok {
		stack[0] = 1
		return
	}

	var err error

	switch fieldKind {
	case api.Kind_Bool:
		err = field.PutBool(data, value != 0)
	case api.Kind_Int8:
		err = field.PutInt8(data, int8(value))
	case api.Kind_Int16:
		err = field.PutInt16(data, int16(value))
	case api.Kind_Int32:
		err = field.PutInt32(data, int32(value))
	case api.Kind_Int64:
		err = field.PutInt64(data, int64(value))
	case api.Kind_Uint8:
		err = field.PutUint8(data, uint8(value))
	case api.Kind_Uint16:
		err = field.PutUint16(data, uint16(value))
	case api.Kind_Uint32:
		err = field.PutUint32(data, uint32(value))
	case api.Kind_Uint64:
		err = field.PutUint64(data, uint64(value))
	case api.Kind_Float32:
		// The guest has to pass it using the IEEE 754 binary representation
		err = field.PutUint32(data, uint32(value))
	case api.Kind_Float64:
		err = field.PutUint64(data, uint64(value))
	case api.Kind_String:
		var str string
		str, err = stringFromStack(m, value)
		if err != nil {
			i.logger.Warnf("fieldSet: reading string from stack: %v", err)
			stack[0] = 1
			return
		}
		err = field.PutString(data, str)
	case api.Kind_Bytes:
		var buf []byte
		buf, err = bufFromStack(m, value)
		if err != nil {
			i.logger.Warnf("reading bytes from stack: %v", err)
			stack[0] = 1
			return
		}
		err = field.PutBytes(data, buf)
	default:
		i.logger.Warnf("unknown field kind: %d", uint32(stack[2]))
		stack[0] = 1
		return
	}

	if err != nil {
		i.logger.Warnf("fieldSet for field %q failed: %v", field.Name(), err)
		stack[0] = 1
		return
	}
}
