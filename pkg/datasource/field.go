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
	"maps"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

type FieldFlag uint32

const (
	// FieldFlagEmpty means the field cannot have a value
	FieldFlagEmpty FieldFlag = 1 << iota

	// FieldFlagContainer means that the field is statically sized and can have multiple statically sized members;
	// AddStaticFields() will return the container for all given fields, and it is assumed, that the creator will
	// always assign the full container using Set()
	FieldFlagContainer

	// FieldFlagHidden sets a field to invisible
	FieldFlagHidden

	// FieldFlagHasParent means that the field is not directly attached to the root of DataSource, but instead to
	// another field that is referenced to in the Parent field
	FieldFlagHasParent

	// FieldFlagStaticMember means that the field is part of a container and is statically sized
	FieldFlagStaticMember

	// FieldFlagUnreferenced means that a field is no longer referenced by its name in the DataSource
	FieldFlagUnreferenced
)

func (f FieldFlag) Uint32() uint32 {
	return uint32(f)
}

func (f FieldFlag) In(of uint32) bool {
	return of&uint32(f) != 0
}

func (f FieldFlag) AddTo(of *uint32) {
	*of |= uint32(f)
}

func (f FieldFlag) RemoveFrom(of *uint32) {
	*of &^= uint32(f)
}

type Field interface {
	FieldName() string
}

type StaticField interface {
	Field
	FieldSize() uint32
	FieldOffset() uint32
}

type AnnotatedField interface {
	FieldAnnotations() map[string]string
}

type TaggedField interface {
	FieldTags() []string
}

type TypedField interface {
	FieldType() api.Kind
}

type FlaggedField interface {
	FieldFlags() FieldFlag
}

type ParentedField interface {
	// FieldParent should return an index to the parent of the field, -1 for no parent
	FieldParent() int
}

type FieldOption func(*field)

func WithKind(kind api.Kind) FieldOption {
	return func(f *field) {
		f.Kind = kind
	}
}

func WithTags(tags ...string) FieldOption {
	return func(f *field) {
		f.Tags = append(f.Tags, tags...)
	}
}

func WithFlags(flags FieldFlag) FieldOption {
	return func(f *field) {
		f.Flags |= uint32(flags)
	}
}

func WithAnnotations(annotations map[string]string) FieldOption {
	return func(f *field) {
		f.Annotations = maps.Clone(annotations)
	}
}

func WithOrder(order int32) FieldOption {
	return func(f *field) {
		f.Order = order
	}
}
