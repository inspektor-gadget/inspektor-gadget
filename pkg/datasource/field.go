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

type FieldFlag uint32

const (
	FieldFlagEmpty FieldFlag = 1 << iota
	FieldFlagContainer
	FieldFlagHidden
	FieldFlagHasParent
	FieldFlagStaticMember
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
	FieldSize() uint32
	FieldOffset() uint32
}

type AnnotatedField interface {
	FieldAnnotations() map[string]string
}

type DescriptionField interface {
	FieldDescription() string
}

type TaggedField interface {
	FieldTags() []string
}

type TypedField interface {
	FieldType() Kind
}

type FlaggedField interface {
	FieldFlags() FieldFlag
}

type ParentedField interface {
	// FieldParent should return an index to the parent of the field, -1 for no parent
	FieldParent() int
}

type Fields []Field

type FieldOption func(*field)

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
