// Copyright 2023 The Inspektor Gadget authors
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

package types

import (
	"reflect"
	"unsafe"

	"golang.org/x/exp/constraints"
)

type EventFactory struct {
	nextOffset uintptr
	nextIndex  int

	setters map[string]any
}

func NewEventFactory() *EventFactory {
	return &EventFactory{
		nextIndex: IndexFixed + 1,
		setters:   make(map[string]any),
	}
}

func (f *EventFactory) NewEvent() *Event {
	ev := &Event{
		Blob: make([][]byte, f.nextIndex),
	}

	ev.Blob[IndexFixed] = make([]byte, f.nextOffset)

	return ev
}

type FieldType interface {
	constraints.Integer | constraints.Float | bool
}

func FactoryAddField[T FieldType](f *EventFactory, name string) ColumnDesc {
	offset := f.nextOffset

	var zero T
	typ := reflect.TypeOf(zero)

	col := ColumnDesc{
		Name: name,
		Type: Type{
			Kind: reflectTypeToKind(typ),
		},
		Offset:    offset,
		BlobIndex: IndexFixed,
	}

	f.nextOffset += typ.Size()

	f.setters[name] = func(ev *Event, v T) {
		*(*T)(unsafe.Pointer(&ev.Blob[IndexFixed][offset])) = v
	}

	return col
}

func FactoryAddString(f *EventFactory, name string) ColumnDesc {
	index := f.nextIndex

	col := ColumnDesc{
		Name: name,
		Type: Type{
			Kind: KindString,
		},
		BlobIndex: index,
	}

	f.nextIndex++

	f.setters[name] = func(ev *Event, v string) {
		ev.Blob[index] = []byte(v)
	}

	return col
}

func GetSetter[T FieldType | string](f *EventFactory, name string) func(*Event, T) {
	return f.setters[name].(func(*Event, T))
}

func reflectTypeToKind(typ reflect.Type) Kind {
	switch typ.Kind() {
	case reflect.Int8:
		return KindInt8
	case reflect.Int16:
		return KindInt16
	case reflect.Int32:
		return KindInt32
	case reflect.Int64:
		return KindInt64
	case reflect.Uint8:
		return KindUint8
	case reflect.Uint16:
		return KindUint16
	case reflect.Uint32:
		return KindUint32
	case reflect.Uint64:
		return KindUint64
	case reflect.Float32:
		return KindFloat32
	case reflect.Float64:
		return KindFloat64
	case reflect.Bool:
		return KindBool
	case reflect.String:
		return KindString
	default:
		return KindNone
	}
}
