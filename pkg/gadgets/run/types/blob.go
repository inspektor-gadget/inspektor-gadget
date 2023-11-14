package types

import (
	"reflect"
	"unsafe"
	//"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
)

const (
	IndexVirtual = -1
	IndexBPF     = 0
	IndexFixed   = 1
)

type BlobEvent struct {
	// [0] is used for bpf event
	// [1] is used for fixed-size members
	// [1+] is used for variable size members
	blob       [][]byte
	lastOffset uintptr
	lastIndex  int
}

func NewBlobEvent() *BlobEvent {
	return &BlobEvent{
		lastIndex: IndexFixed + 1,
	}
}

func (e *BlobEvent) Allocate() {
	e.blob = make([][]byte, e.lastIndex)
	e.blob[1] = make([]byte, e.lastOffset)
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

type FieldType interface {
	int8 | int16 | int32 | int64 |
		uint8 | uint16 | uint32 | uint64 |
		float32 | float64 | bool
}

func AddField[T FieldType](e *BlobEvent, name string) (ColumnDesc, func(ev *BlobEvent, v T)) {
	offset := e.lastOffset

	var zero T
	typ := reflect.TypeOf(zero)

	col := ColumnDesc{
		Name: name,
		Type: Type{
			Kind: reflectTypeToKind(typ),
		},
		Offset: offset,
		Index:  IndexFixed,
	}

	e.lastOffset += typ.Size()

	setter := func(ev *BlobEvent, v T) {
		*(*T)(unsafe.Pointer(&ev.blob[IndexFixed][offset])) = v
	}

	return col, setter
}

func (e *BlobEvent) AddString(name string) (ColumnDesc, func(ev *BlobEvent, v string)) {
	index := e.lastIndex

	col := ColumnDesc{
		Name: name,
		Type: Type{
			Kind: KindString,
		},
		Index: index,
	}

	e.lastIndex++

	setter := func(ev *BlobEvent, v string) {
		e.blob[index] = []byte(v)
	}

	return col, setter
}

func (e *BlobEvent) Blob() [][]byte {
	return e.blob
}
