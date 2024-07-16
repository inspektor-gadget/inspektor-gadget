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

package datasource

import (
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"unsafe"

	"golang.org/x/exp/constraints"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

type InvalidFieldLengthErr struct {
	Expected int
	Actual   int
}

func (e *InvalidFieldLengthErr) Error() string {
	return fmt.Sprintf("invalid field length, expected %d, got %d", e.Expected, e.Actual)
}

func invalidFieldLengthErr(size, expected int) error {
	return &InvalidFieldLengthErr{
		Expected: expected,
		Actual:   size,
	}
}

type InvalidMultipleOfFieldLengthErr struct {
	Expected int
	Actual   int
}

func (e *InvalidMultipleOfFieldLengthErr) Error() string {
	return fmt.Sprintf("invalid field length, expected multiple of %d, got %d", e.Expected, e.Actual)
}

func invalidMultipleOfFieldLengthErr(size, expected int) error {
	return &InvalidMultipleOfFieldLengthErr{
		Expected: expected,
		Actual:   size,
	}
}

// FieldAccessor grants access to the underlying buffer of a field
type FieldAccessor interface {
	Name() string
	FullName() string

	// Size returns the expected size of the underlying field or zero, if the field has a dynamic size
	Size() uint32

	// Get returns the underlying memory of the field
	Get(data Data) []byte

	// Set sets value as the new reference for the field; if the FieldAccessor is used for the member of a
	// statically sized payload (for example a member of an eBPF struct), value will be copied to the existing
	// memory instead.
	Set(data Data, value []byte) error

	// IsRequested returns whether the consumer is interested in this field; if not, operators are not required
	// to fill them out
	IsRequested() bool

	// AddSubField adds a new field as member of the current field; be careful when doing this on an existing
	// non-empty field, as that might be dropped on serialization // TODO
	AddSubField(name string, kind api.Kind, opts ...FieldOption) (FieldAccessor, error)

	// GetSubFieldsWithTag returns all SubFields matching any given tag
	GetSubFieldsWithTag(tag ...string) []FieldAccessor

	// Parent returns the parent of this field, if this field is a SubField
	Parent() FieldAccessor

	// SubFields returns all existing SubFields of the current field
	SubFields() []FieldAccessor

	// SetHidden marks a field as hidden (by default) - it can still be requested
	SetHidden(hidden bool, recurse bool)

	// Type returns the underlying type of the field
	Type() api.Kind

	// Flags returns the flags of the field
	Flags() uint32

	// Tags returns all tags of the field
	Tags() []string

	// HasAllTagsOf checks whether the field has all given tags
	HasAllTagsOf(tags ...string) bool

	// HasAnyTagsOf checks whether the field has any of the given tags; if tags is empty, it returns false
	HasAnyTagsOf(tags ...string) bool

	// Annotations returns stored annotations of the field
	Annotations() map[string]string

	// AddAnnotation sets a new annotation for the field
	AddAnnotation(key, value string)

	// RemoveReference removes the reference by name from the hierarchy, effectively freeing the name
	// tbd: name
	RemoveReference(recurse bool)

	// Rename changes the name of the field. Currently it's not supported for subfields.
	Rename(string) error

	Uint8(Data) (uint8, error)
	Uint16(Data) (uint16, error)
	Uint32(Data) (uint32, error)
	Uint64(Data) (uint64, error)
	Int8(Data) (int8, error)
	Int16(Data) (int16, error)
	Int32(Data) (int32, error)
	Int64(Data) (int64, error)
	Float32(Data) (float32, error)
	Float64(Data) (float64, error)
	String(Data) (string, error)
	Bytes(Data) ([]byte, error)
	Bool(Data) (bool, error)

	Uint8Array(Data) ([]uint8, error)
	Uint16Array(Data) ([]uint16, error)
	Uint32Array(Data) ([]uint32, error)
	Uint64Array(Data) ([]uint64, error)
	Int8Array(Data) ([]int8, error)
	Int16Array(Data) ([]int16, error)
	Int32Array(Data) ([]int32, error)
	Int64Array(Data) ([]int64, error)
	Float32Array(Data) ([]float32, error)
	Float64Array(Data) ([]float64, error)

	PutUint8(Data, uint8) error
	PutUint16(Data, uint16) error
	PutUint32(Data, uint32) error
	PutUint64(Data, uint64) error
	PutInt8(Data, int8) error
	PutInt16(Data, int16) error
	PutInt32(Data, int32) error
	PutInt64(Data, int64) error
	PutFloat32(Data, float32) error
	PutFloat64(Data, float64) error
	PutString(Data, string) error
	PutBytes(Data, []byte) error
	PutBool(Data, bool) error
}

type fieldAccessor struct {
	ds *dataSource
	f  *field
}

func (a *fieldAccessor) Name() string {
	return a.f.Name
}

func (a *fieldAccessor) FullName() string {
	return a.f.FullName
}

func (a *fieldAccessor) Rename(name string) error {
	a.ds.lock.Lock()
	defer a.ds.lock.Unlock()

	if _, ok := a.ds.fieldMap[name]; ok {
		return fmt.Errorf("field with name %q already exists", name)
	}

	if a.f.Name != a.f.FullName {
		return errors.New("Rename() not supported for subfields")
	}

	delete(a.ds.fieldMap, a.f.FullName)

	a.f.Name = name
	a.f.FullName = name
	a.ds.fieldMap[name] = a.f

	return nil
}

func (a *fieldAccessor) Size() uint32 {
	return a.f.Size
}

func (a *fieldAccessor) Type() api.Kind {
	return a.f.Kind
}

func (a *fieldAccessor) Get(d Data) []byte {
	if FieldFlagEmpty.In(a.f.Flags) {
		return nil
	}
	if a.f.Size > 0 {
		// size and offset must be valid here; checks take place on initialization
		return d.payload()[a.f.PayloadIndex][a.f.Offs : a.f.Offs+a.f.Size]
	}
	return d.payload()[a.f.PayloadIndex]
}

func (a *fieldAccessor) setHidden(hidden bool, recurse bool) {
	if !hidden {
		FieldFlagHidden.RemoveFrom(&a.f.Flags)
	} else {
		FieldFlagHidden.AddTo(&a.f.Flags)
	}
	if recurse {
		for _, acc := range a.subFields() {
			acc.(*fieldAccessor).setHidden(hidden, recurse)
		}
	}
}

func (a *fieldAccessor) SetHidden(hidden bool, recurse bool) {
	a.ds.lock.Lock()
	defer a.ds.lock.Unlock()
	a.setHidden(hidden, recurse)
}

func (a *fieldAccessor) Set(d Data, b []byte) error {
	if FieldFlagEmpty.In(a.f.Flags) {
		return errors.New("field cannot contain a value")
	}
	if FieldFlagStaticMember.In(a.f.Flags) {
		// If it's a short string copy it and clean the rest with 0s
		if (a.f.Kind == api.Kind_String || a.f.Kind == api.Kind_CString) && uint32(len(b)) < a.f.Size {
			copy(d.payload()[a.f.PayloadIndex][a.f.Offs:a.f.Offs+a.f.Size], b)

			for i := uint32(len(b)); i < a.f.Size; i++ {
				d.payload()[a.f.PayloadIndex][a.f.Offs+i] = 0
			}
			return nil
		}

		if uint32(len(b)) != a.f.Size {
			return invalidFieldLengthErr(len(b), int(a.f.Size))
		}
		// When accessing a member of a statically sized field, copy memory
		copy(d.payload()[a.f.PayloadIndex][a.f.Offs:a.f.Offs+a.f.Size], b)
		return nil
	}
	if FieldFlagContainer.In(a.f.Flags) {
		if uint32(len(b)) != a.f.Size {
			return invalidFieldLengthErr(len(b), int(a.f.Size))
		}
	}
	d.payload()[a.f.PayloadIndex] = b
	return nil
}

func (a *fieldAccessor) removeReference(recurse bool) {
	// Add flag and remove from fieldMap
	FieldFlagUnreferenced.AddTo(&a.f.Flags)
	delete(a.ds.fieldMap, a.f.FullName)
	if recurse {
		for _, acc := range a.subFields() {
			acc.(*fieldAccessor).removeReference(recurse)
		}
	}
}

func (a *fieldAccessor) RemoveReference(recurse bool) {
	a.ds.lock.Lock()
	defer a.ds.lock.Unlock()
	a.removeReference(recurse)
}

func (a *fieldAccessor) AddSubField(name string, kind api.Kind, opts ...FieldOption) (FieldAccessor, error) {
	a.ds.lock.Lock()
	defer a.ds.lock.Unlock()

	parentFullName, err := resolveNames(a.f.Index, a.ds.fields, 0)
	if err != nil {
		return nil, fmt.Errorf("resolving parent field name: %w", err)
	}

	nf := &field{
		Name:        name,
		FullName:    parentFullName + "." + name,
		Kind:        kind,
		Parent:      a.f.Index,
		Index:       uint32(len(a.ds.fields)),
		Annotations: maps.Clone(defaultFieldAnnotations),
	}
	for _, opt := range opts {
		opt(nf)
	}

	if _, ok := a.ds.fieldMap[nf.FullName]; ok {
		return nil, fmt.Errorf("field with name %q already exists", nf.FullName)
	}

	FieldFlagHasParent.AddTo(&nf.Flags)

	if !FieldFlagEmpty.In(nf.Flags) {
		nf.PayloadIndex = a.ds.payloadCount
		a.ds.payloadCount++
	}

	a.ds.applyFieldConfig(nf)

	a.ds.fields = append(a.ds.fields, nf)
	a.ds.fieldMap[nf.FullName] = nf
	return &fieldAccessor{ds: a.ds, f: nf}, nil
}

func (a *fieldAccessor) subFields() []FieldAccessor {
	var res []FieldAccessor
	for _, f := range a.ds.fields {
		if !FieldFlagHasParent.In(f.Flags) {
			continue
		}
		if f.Parent != a.f.Index {
			continue
		}
		res = append(res, &fieldAccessor{
			ds: a.ds,
			f:  f,
		})
	}
	return res
}

func (a *fieldAccessor) SubFields() []FieldAccessor {
	a.ds.lock.RLock()
	defer a.ds.lock.RUnlock()
	return a.subFields()
}

func (a *fieldAccessor) Parent() FieldAccessor {
	a.ds.lock.RLock()
	defer a.ds.lock.RUnlock()

	if !FieldFlagHasParent.In(a.f.Flags) {
		return nil
	}
	if a.f.Parent >= uint32(len(a.ds.fields)) {
		return nil
	}
	return &fieldAccessor{ds: a.ds, f: a.ds.fields[a.f.Parent]}
}

func (a *fieldAccessor) GetSubFieldsWithTag(tag ...string) []FieldAccessor {
	a.ds.lock.RLock()
	defer a.ds.lock.RUnlock()

	res := make([]FieldAccessor, 0)
	for _, f := range a.ds.fields {
		if !FieldFlagHasParent.In(f.Flags) {
			continue
		}
		if f.Parent != a.f.Index {
			continue
		}
		for _, t := range tag {
			if slices.Contains(f.Tags, t) {
				res = append(res, &fieldAccessor{ds: a.ds, f: f})
				break
			}
		}
	}
	return res
}

func (a *fieldAccessor) IsRequested() bool {
	return a.ds.IsRequestedField(a.f.Name)
}

func (a *fieldAccessor) Flags() uint32 {
	return a.f.Flags
}

func (a *fieldAccessor) Tags() []string {
	return slices.Clone(a.f.Tags)
}

func (a *fieldAccessor) HasAllTagsOf(tags ...string) bool {
	for _, tag := range tags {
		if !slices.Contains(a.f.Tags, tag) {
			return false
		}
	}
	return true
}

func (a *fieldAccessor) HasAnyTagsOf(tags ...string) bool {
	for _, tag := range tags {
		if slices.Contains(a.f.Tags, tag) {
			return true
		}
	}
	return false
}

func (a *fieldAccessor) Annotations() map[string]string {
	if a.f.Annotations == nil {
		// Return an empty map to allow access without prior checks
		return map[string]string{}
	}
	// return a clone to avoid write access
	return maps.Clone(a.f.Annotations)
}

func (a *fieldAccessor) AddAnnotation(key, value string) {
	if a.f.Annotations == nil {
		a.f.Annotations = map[string]string{}
	}
	a.f.Annotations[key] = value
}

func (a *fieldAccessor) Uint8(data Data) (uint8, error) {
	val := a.Get(data)
	if len(val) != 1 {
		return 0, invalidFieldLengthErr(len(val), 1)
	}
	return val[0], nil
}

func (a *fieldAccessor) Uint16(data Data) (uint16, error) {
	val := a.Get(data)
	if len(val) != 2 {
		return 0, invalidFieldLengthErr(len(val), 2)
	}
	return a.ds.byteOrder.Uint16(val), nil
}

func (a *fieldAccessor) Uint32(data Data) (uint32, error) {
	val := a.Get(data)
	if len(val) != 4 {
		return 0, invalidFieldLengthErr(len(val), 4)
	}
	return a.ds.byteOrder.Uint32(val), nil
}

func (a *fieldAccessor) Uint64(data Data) (uint64, error) {
	val := a.Get(data)
	if len(val) != 8 {
		return 0, invalidFieldLengthErr(len(val), 8)
	}
	return a.ds.byteOrder.Uint64(val), nil
}

func (a *fieldAccessor) Int8(data Data) (int8, error) {
	val := a.Get(data)
	if len(val) != 1 {
		return 0, invalidFieldLengthErr(len(val), 1)
	}
	return int8(val[0]), nil
}

func (a *fieldAccessor) Int16(data Data) (int16, error) {
	val := a.Get(data)
	if len(val) != 2 {
		return 0, invalidFieldLengthErr(len(val), 2)
	}
	return int16(a.ds.byteOrder.Uint16(val)), nil
}

func (a *fieldAccessor) Int32(data Data) (int32, error) {
	val := a.Get(data)
	if len(val) != 4 {
		return 0, invalidFieldLengthErr(len(val), 4)
	}
	return int32(a.ds.byteOrder.Uint32(val)), nil
}

func (a *fieldAccessor) Int64(data Data) (int64, error) {
	val := a.Get(data)
	if len(val) != 8 {
		return 0, invalidFieldLengthErr(len(val), 8)
	}
	return int64(a.ds.byteOrder.Uint64(val)), nil
}

func (a *fieldAccessor) Float32(data Data) (float32, error) {
	i, err := a.Uint32(data)
	if err != nil {
		return 0.0, err
	}
	return math.Float32frombits(i), nil
}

func (a *fieldAccessor) Float64(data Data) (float64, error) {
	i, err := a.Uint64(data)
	if err != nil {
		return 0.0, err
	}
	return math.Float64frombits(i), nil
}

// Array functions
// to be discussed: these methods use a slow copying method to return the arrays
// It can also be done using for the unsafe package, like:
// return unsafe.Slice((*uint64)(unsafe.Pointer(&val[0])), len(val)/8), nil
// I _think_ it's okay, but if there are any reasons against it, please let me know.

func copyArray[T constraints.Integer | constraints.Float](a *fieldAccessor, data Data, convert func([]byte) T) ([]T, error) {
	var s T
	size := int(unsafe.Sizeof(s))
	val := a.Get(data)
	if len(val)%size != 0 {
		return nil, invalidMultipleOfFieldLengthErr(len(val), size)
	}
	res := make([]T, 0, len(val)/size)
	for i := 0; i < len(val); i += size {
		res = append(res, convert(val[i:i+size]))
	}
	return res, nil
}

func (a *fieldAccessor) Uint8Array(data Data) ([]uint8, error) {
	return copyArray(a, data, func(v []byte) uint8 { return v[0] })
}

func (a *fieldAccessor) Uint16Array(data Data) ([]uint16, error) {
	return copyArray(a, data, a.ds.byteOrder.Uint16)
}

func (a *fieldAccessor) Uint32Array(data Data) ([]uint32, error) {
	return copyArray(a, data, a.ds.byteOrder.Uint32)
}

func (a *fieldAccessor) Uint64Array(data Data) ([]uint64, error) {
	return copyArray(a, data, a.ds.byteOrder.Uint64)
}

func (a *fieldAccessor) Int8Array(data Data) ([]int8, error) {
	return copyArray(a, data, func(v []byte) int8 { return int8(v[0]) })
}

func (a *fieldAccessor) Int16Array(data Data) ([]int16, error) {
	return copyArray(a, data, func(v []byte) int16 { return int16(a.ds.byteOrder.Uint16(v)) })
}

func (a *fieldAccessor) Int32Array(data Data) ([]int32, error) {
	return copyArray(a, data, func(v []byte) int32 { return int32(a.ds.byteOrder.Uint32(v)) })
}

func (a *fieldAccessor) Int64Array(data Data) ([]int64, error) {
	return copyArray(a, data, func(v []byte) int64 { return int64(a.ds.byteOrder.Uint64(v)) })
}

func (a *fieldAccessor) Float32Array(data Data) ([]float32, error) {
	return copyArray(a, data, func(v []byte) float32 { return math.Float32frombits(a.ds.byteOrder.Uint32(v)) })
}

func (a *fieldAccessor) Float64Array(data Data) ([]float64, error) {
	return copyArray(a, data, func(v []byte) float64 { return math.Float64frombits(a.ds.byteOrder.Uint64(v)) })
}

func (a *fieldAccessor) String(data Data) (string, error) {
	if a.f.Kind == api.Kind_CString {
		in := a.Get(data)
		for i := 0; i < len(in); i++ {
			if in[i] == 0 {
				return string(in[:i]), nil
			}
		}
		return string(in), nil
	}
	return string(a.Get(data)), nil
}

func (a *fieldAccessor) Bytes(data Data) ([]byte, error) {
	return a.Get(data), nil
}

func (a *fieldAccessor) Bool(data Data) (bool, error) {
	val := a.Get(data)
	if len(val) != 1 {
		return false, invalidFieldLengthErr(len(val), 1)
	}
	return val[0] == 1, nil
}

func (a *fieldAccessor) PutUint8(data Data, val uint8) error {
	b := a.Get(data)
	if len(b) != 1 {
		return invalidFieldLengthErr(len(b), 1)
	}
	b[0] = val
	return nil
}

func (a *fieldAccessor) PutUint16(data Data, val uint16) error {
	b := a.Get(data)
	if len(b) != 2 {
		return invalidFieldLengthErr(len(b), 2)
	}
	a.ds.byteOrder.PutUint16(b, val)
	return nil
}

func (a *fieldAccessor) PutUint32(data Data, val uint32) error {
	b := a.Get(data)
	if len(b) != 4 {
		return invalidFieldLengthErr(len(b), 4)
	}
	a.ds.byteOrder.PutUint32(b, val)
	return nil
}

func (a *fieldAccessor) PutUint64(data Data, val uint64) error {
	b := a.Get(data)
	if len(b) != 8 {
		return invalidFieldLengthErr(len(b), 8)
	}
	a.ds.byteOrder.PutUint64(a.Get(data), val)
	return nil
}

func (a *fieldAccessor) PutInt8(data Data, val int8) error {
	b := a.Get(data)
	if len(b) != 1 {
		return invalidFieldLengthErr(len(b), 1)
	}
	b[0] = uint8(val)
	return nil
}

func (a *fieldAccessor) PutInt16(data Data, val int16) error {
	b := a.Get(data)
	if len(b) != 2 {
		return invalidFieldLengthErr(len(b), 2)
	}
	a.ds.byteOrder.PutUint16(b, uint16(val))
	return nil
}

func (a *fieldAccessor) PutInt32(data Data, val int32) error {
	b := a.Get(data)
	if len(b) != 4 {
		return invalidFieldLengthErr(len(b), 4)
	}
	a.ds.byteOrder.PutUint32(b, uint32(val))
	return nil
}

func (a *fieldAccessor) PutInt64(data Data, val int64) error {
	b := a.Get(data)
	if len(b) != 8 {
		return invalidFieldLengthErr(len(b), 8)
	}
	a.ds.byteOrder.PutUint64(b, uint64(val))
	return nil
}

func (a *fieldAccessor) PutFloat32(data Data, val float32) error {
	return a.PutUint32(data, math.Float32bits(val))
}

func (a *fieldAccessor) PutFloat64(data Data, val float64) error {
	return a.PutUint64(data, math.Float64bits(val))
}

func (a *fieldAccessor) PutString(data Data, val string) error {
	return a.Set(data, []byte(val))
}

func (a *fieldAccessor) PutBytes(data Data, val []byte) error {
	return a.Set(data, val)
}

func (a *fieldAccessor) PutBool(data Data, val bool) error {
	b := a.Get(data)
	if len(b) != 1 {
		return invalidFieldLengthErr(len(b), 1)
	}

	if val {
		b[0] = 1
	} else {
		b[0] = 0
	}
	return nil
}
