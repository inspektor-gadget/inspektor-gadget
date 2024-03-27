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

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
)

// FieldAccessor grants access to the underlying buffer of a field
type FieldAccessor interface {
	Name() string

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
	AddSubField(name string, opts ...FieldOption) (FieldAccessor, error)

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

	// Annotations returns stored annotations of the field
	Annotations() map[string]string

	// RemoveReference removes the reference by name from the hierarchy, effectively freeing the name
	// tbd: name
	RemoveReference(recurse bool)

	Uint8(Data) uint8
	Uint16(Data) uint16
	Uint32(Data) uint32
	Uint64(Data) uint64
	Int8(Data) int8
	Int16(Data) int16
	Int32(Data) int32
	Int64(Data) int64

	Float32(Data) float32
	Float64(Data) float64

	PutUint8(Data, uint8)
	PutUint16(Data, uint16)
	PutUint32(Data, uint32)
	PutUint64(Data, uint64)
	PutInt8(Data, int8)
	PutInt16(Data, int16)
	PutInt32(Data, int32)
	PutInt64(Data, int64)

	String(Data) string
	CString(Data) string
}

type fieldAccessor struct {
	ds *dataSource
	f  *field
}

func (a *fieldAccessor) Name() string {
	return a.f.Name
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
		return d.(*data).Payload[a.f.PayloadIndex][a.f.Offs : a.f.Offs+a.f.Size]
	}
	return d.(*data).Payload[a.f.PayloadIndex]
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
		if uint32(len(b)) != a.f.Size {
			return fmt.Errorf("invalid size, static member expected %d, got %d", a.f.Size, len(b))
		}
		// When accessing a member of a statically sized field, copy memory
		copy(d.Raw().Payload[a.f.PayloadIndex][a.f.Offs:a.f.Offs+a.f.Size], b)
		return nil
	}
	if FieldFlagContainer.In(a.f.Flags) {
		if uint32(len(b)) != a.f.Size {
			return fmt.Errorf("invalid size, container expected %d, got %d", a.f.Size, len(b))
		}
	}
	d.(*data).Payload[a.f.PayloadIndex] = b
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

func (a *fieldAccessor) AddSubField(name string, opts ...FieldOption) (FieldAccessor, error) {
	a.ds.lock.Lock()
	defer a.ds.lock.Unlock()

	parentFullName, err := resolveNames(a.f.Index, a.ds.fields, 0)
	if err != nil {
		return nil, fmt.Errorf("resolving parent field name: %w", err)
	}

	nf := &field{
		Name:     name,
		FullName: parentFullName + "." + name,
		Kind:     api.Kind_Invalid,
		Parent:   a.f.Index,
		Index:    uint32(len(a.ds.fields)),
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

func (a *fieldAccessor) Annotations() map[string]string {
	if a.f.Annotations == nil {
		// Return an empty map to allow access without prior checks
		return map[string]string{}
	}
	// return a clone to avoid write access
	return maps.Clone(a.f.Annotations)
}

func (a *fieldAccessor) Uint8(data Data) uint8 {
	val := a.Get(data)
	if len(val) < 1 {
		return 0
	}
	return val[0]
}

func (a *fieldAccessor) Uint16(data Data) uint16 {
	val := a.Get(data)
	if len(val) < 2 {
		return 0
	}
	return a.ds.byteOrder.Uint16(val)
}

func (a *fieldAccessor) Uint32(data Data) uint32 {
	val := a.Get(data)
	if len(val) < 4 {
		return 0
	}
	return a.ds.byteOrder.Uint32(val)
}

func (a *fieldAccessor) Uint64(data Data) uint64 {
	val := a.Get(data)
	if len(val) < 8 {
		return 0
	}
	return a.ds.byteOrder.Uint64(val)
}

func (a *fieldAccessor) Int8(data Data) int8 {
	val := a.Get(data)
	if len(val) < 1 {
		return 0
	}
	return int8(val[0])
}

func (a *fieldAccessor) Int16(data Data) int16 {
	val := a.Get(data)
	if len(val) < 2 {
		return 0
	}
	return int16(a.ds.byteOrder.Uint16(val))
}

func (a *fieldAccessor) Int32(data Data) int32 {
	val := a.Get(data)
	if len(val) < 4 {
		return 0
	}
	return int32(a.ds.byteOrder.Uint32(val))
}

func (a *fieldAccessor) Int64(data Data) int64 {
	val := a.Get(data)
	if len(val) < 8 {
		return 0
	}
	return int64(a.ds.byteOrder.Uint64(val))
}

func (a *fieldAccessor) Float32(data Data) float32 {
	return math.Float32frombits(a.Uint32(data))
}

func (a *fieldAccessor) Float64(data Data) float64 {
	return math.Float64frombits(a.Uint64(data))
}

func (a *fieldAccessor) String(data Data) string {
	return string(a.Get(data))
}

func (a *fieldAccessor) CString(data Data) string {
	return gadgets.FromCString(a.Get(data))
}

func (a *fieldAccessor) PutUint8(data Data, val uint8) {
	a.Get(data)[0] = val
}

func (a *fieldAccessor) PutUint16(data Data, val uint16) {
	a.ds.byteOrder.PutUint16(a.Get(data), val)
}

func (a *fieldAccessor) PutUint32(data Data, val uint32) {
	a.ds.byteOrder.PutUint32(a.Get(data), val)
}

func (a *fieldAccessor) PutUint64(data Data, val uint64) {
	a.ds.byteOrder.PutUint64(a.Get(data), val)
}

func (a *fieldAccessor) PutInt8(data Data, val int8) {
	a.Get(data)[0] = uint8(val)
}

func (a *fieldAccessor) PutInt16(data Data, val int16) {
	a.ds.byteOrder.PutUint16(a.Get(data), uint16(val))
}

func (a *fieldAccessor) PutInt32(data Data, val int32) {
	a.ds.byteOrder.PutUint32(a.Get(data), uint32(val))
}

func (a *fieldAccessor) PutInt64(data Data, val int64) {
	a.ds.byteOrder.PutUint64(a.Get(data), uint64(val))
}
