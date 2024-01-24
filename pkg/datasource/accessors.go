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
	"slices"
)

// FieldAccessor grants access to the underlying buffer of a field
type FieldAccessor interface {
	Name() string

	// Size returns the expected size of the underlying field or zero, if the field has a dynamic size
	Size() uint32

	// Get returns the underlying memory of the field
	Get(data Data) []byte

	// Set sets value as the new reference for the field; if the FieldAccessor is used for the member of a
	// statically sized payload (for example a member of an eBPF struct), value will be copied to the existin
	// memory instead.
	Set(data Data, value []byte) error

	// IsRequested returns whether the consumer is interested in this field; if not, operators are not required
	// to will them out
	IsRequested() bool

	// AddSubField adds a new field as member of the current field; be careful when doing this on an existing
	// non-empty field, as that might be dropped on serialization // TODO
	AddSubField(name string, opts ...FieldOption) (FieldAccessor, error)

	// GetSubFieldsWithTag returns all SubFields matching all given tags
	GetSubFieldsWithTag(tag ...string) []FieldAccessor

	// Parent returns the parent of this field, if this field is a SubField
	Parent() FieldAccessor

	// SubFields returns all existing SubFields of the current field
	SubFields() []FieldAccessor

	// SetHidden marks a field as hidden (by default) - it can still be requested
	SetHidden(bool)
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

func (a *fieldAccessor) Get(d Data) []byte {
	if FieldFlagEmpty.In(a.f.Flags) {
		return nil
	}
	if a.f.Size > 0 {
		// size must be valid here
		return d.(*data).Payload[a.f.PayloadIndex][a.f.Offs : a.f.Offs+a.f.Size]
	}
	return d.(*data).Payload[a.f.PayloadIndex]
}

func (a *fieldAccessor) SetHidden(val bool) {
	a.ds.lock.Lock()
	defer a.ds.lock.Unlock()
	if !val {
		FieldFlagHidden.RemoveFrom(&a.f.Flags)
	} else {
		FieldFlagHidden.AddTo(&a.f.Flags)
	}
}

func (a *fieldAccessor) Set(d Data, b []byte) error {
	if FieldFlagEmpty.In(a.f.Flags) {
		return errors.New("field cannot contain a value")
	}
	if a.f.Size != 0 && uint32(len(b)) != a.f.Size {
		return fmt.Errorf("invalid size, expected %d, got %d", a.f.Size, len(b))
	}
	if FieldFlagStaticMember.In(a.f.Flags) {
		// When accessing a member of a statically sized field, copy memory
		copy(d.Raw().Payload[a.f.PayloadIndex][a.f.Offs:a.f.Offs+a.f.Size], b)
	}
	d.(*data).Payload[a.f.PayloadIndex] = b
	return nil
}

func (a *fieldAccessor) AddSubField(name string, opts ...FieldOption) (FieldAccessor, error) {
	a.ds.lock.Lock()
	defer a.ds.lock.Unlock()

	name = a.f.Name + "." + name

	nf := &field{
		Name:   name,
		Type:   uint32(Slice),
		Parent: a.f.Index,
	}
	for _, opt := range opts {
		opt(nf)
	}
	FieldFlagHasParent.AddTo(&nf.Flags)

	if !FieldFlagEmpty.In(nf.Flags) {
		nf.PayloadIndex = a.ds.payloadCount
		a.ds.payloadCount++
	}

	a.ds.fields = append(a.ds.fields, nf)
	a.ds.fieldMap[nf.Name] = nf
	return &fieldAccessor{ds: a.ds, f: nf}, nil
}

func (a *fieldAccessor) SubFields() []FieldAccessor {
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

func (a *fieldAccessor) Parent() FieldAccessor {
	if !FieldFlagHasParent.In(a.f.Flags) {
		return nil
	}
	if a.f.Parent >= uint32(len(a.ds.fields)) {
		return nil
	}
	return &fieldAccessor{ds: a.ds, f: a.ds.fields[a.f.Parent]}
}

func (a *fieldAccessor) GetSubFieldsWithTag(tag ...string) []FieldAccessor {
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
			}
		}
	}
	return res
}

func (a *fieldAccessor) IsRequested() bool {
	return a.ds.IsRequestedField(a.f.Name)
}
