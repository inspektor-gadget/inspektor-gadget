package tracer

import (
	"reflect"
	"unsafe"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
)

const (
	indexVirtual = -1
	indexBPF     = 0
	indexFixed   = 1
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
		lastIndex: indexFixed + 1,
	}
}

func (e *BlobEvent) Allocate() {
	e.blob = make([][]byte, e.lastIndex)
	e.blob[1] = make([]byte, e.lastOffset)
}

func reflectTypeToKind(typ reflect.Type) types.Kind {
	switch typ.Kind() {
	case reflect.Int8:
		return types.KindInt8
	case reflect.Int16:
		return types.KindInt16
	case reflect.Int32:
		return types.KindInt32
	case reflect.Int64:
		return types.KindInt64
	case reflect.Uint8:
		return types.KindUint8
	case reflect.Uint16:
		return types.KindUint16
	case reflect.Uint32:
		return types.KindUint32
	case reflect.Uint64:
		return types.KindUint64
	case reflect.Float32:
		return types.KindFloat32
	case reflect.Float64:
		return types.KindFloat64
	case reflect.Bool:
		return types.KindBool
	case reflect.String:
		return types.KindString
	default:
		return types.KindNone
	}
}

type FieldType interface {
	int8 | int16 | int32 | int64 |
		uint8 | uint16 | uint32 | uint64 |
		float32 | float64 | bool
}

func AddField[T FieldType](e *BlobEvent, name string) (types.ColumnDesc, func(ev *BlobEvent, v T)) {
	offset := e.lastOffset

	var zero T
	typ := reflect.TypeOf(zero)

	col := types.ColumnDesc{
		Name: name,
		Type: types.Type{
			Kind: reflectTypeToKind(typ),
		},
		Offset: offset,
		Index:  indexFixed,
	}

	e.lastOffset += typ.Size()

	setter := func(ev *BlobEvent, v T) {
		*(*T)(unsafe.Pointer(&ev.blob[indexFixed][offset])) = v
	}

	return col, setter
}

func (e *BlobEvent) AddString(name string) (types.ColumnDesc, func(ev *BlobEvent, v string)) {
	index := e.lastIndex

	col := types.ColumnDesc{
		Name: name,
		Type: types.Type{
			Kind: types.KindString,
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
