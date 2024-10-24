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

package ebpfoperator

import (
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/cilium/ebpf/btf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/btfhelpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	metadatav1 "github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1"
	ebpftypes "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/types"
)

type Field struct {
	Tags        []string
	Annotations map[string]string
	Offset      uint32
	Size        uint32
	parent      int
	name        string
	kind        api.Kind
}

type Struct struct {
	Fields []*Field
	Size   uint32
}

type enum struct {
	*btf.Enum
	memberName string
}

func (f *Field) FieldName() string {
	return f.name
}

func (f *Field) FieldSize() uint32 {
	return f.Size
}

func (f *Field) FieldOffset() uint32 {
	return f.Offset
}

func (f *Field) FieldTags() []string {
	return f.Tags
}

func (f *Field) FieldType() api.Kind {
	return f.kind
}

func (f *Field) FieldParent() int {
	return f.parent
}

func (f *Field) FieldAnnotations() map[string]string {
	return maps.Clone(f.Annotations)
}

func (i *ebpfInstance) populateStructDirect(btfStruct *btf.Struct) error {
	gadgetStruct := i.structs[btfStruct.Name]

	if gadgetStruct == nil {
		gadgetStruct = &Struct{}
		i.logger.Debugf("adding struct %q", btfStruct.Name)
	}

	i.getFieldsFromStruct(btfStruct, &gadgetStruct.Fields, "", 0, -1)

	gadgetStruct.Size = btfStruct.Size

	i.structs[btfStruct.Name] = gadgetStruct
	return nil
}

func getFieldKind(typ reflect.Type, tags []string) api.Kind {
	if typ == nil {
		return api.Kind_Invalid
	}

	switch typ.Kind() {
	case reflect.Bool:
		return api.Kind_Bool
	case reflect.Int8:
		return api.Kind_Int8
	case reflect.Int16:
		return api.Kind_Int16
	case reflect.Int32:
		return api.Kind_Int32
	case reflect.Int64:
		return api.Kind_Int64
	case reflect.Uint8:
		return api.Kind_Uint8
	case reflect.Uint16:
		return api.Kind_Uint16
	case reflect.Uint32:
		return api.Kind_Uint32
	case reflect.Uint64:
		return api.Kind_Uint64
	case reflect.Float32:
		return api.Kind_Float32
	case reflect.Float64:
		return api.Kind_Float64
	case reflect.Array:
		// Special case to handle char arrays as strings
		// TODO: Handle other cases once we support arrays
		if typ.Elem().Kind() == reflect.Int8 && slices.Contains(tags, "type:char") {
			return api.Kind_CString
		}
		kind := getFieldKind(typ.Elem(), tags)
		if api.IsArrayKind(kind) {
			// we don't support arrays of arrays for now
			return api.Kind_Invalid
		}
		return api.ArrayOf(kind)
	}
	return api.Kind_Invalid
}

func applyAnnotationsTemplateForType(typeName string, dst map[string]string) bool {
	switch typeName {
	case ebpftypes.CommTypeName,
		ebpftypes.UidTypeName,
		ebpftypes.GidTypeName,
		ebpftypes.PidTypeName,
		ebpftypes.TidTypeName,
		ebpftypes.TimestampTypeName,
		ebpftypes.MntNsTypeName,
		ebpftypes.NetNsTypeName,
		ebpftypes.PcommTypeName,
		ebpftypes.PpidTypeName:
		return metadatav1.ApplyAnnotationsTemplate(strings.TrimPrefix(typeName, "gadget_"), dst)
	}
	return false
}

func (i *ebpfInstance) getFieldsFromMember(member btf.Member, fields *[]*Field, prefix string, offset uint32, parent int) {
	annotations := make(map[string]string)
	refType, tags := btfhelpers.GetType(member.Type)
	for i := range tags {
		applyAnnotationsTemplateForType(tags[i], annotations)
		tags[i] = "type:" + tags[i]
	}

	tags = append(tags, "name:"+member.Name, api.TagSrcEbpf)

	newField := func(size uint32, kind api.Kind) *Field {
		return &Field{
			Size:        size,
			Tags:        tags,
			Offset:      offset + member.Offset.Bytes(),
			parent:      parent,
			name:        member.Name,
			kind:        kind,
			Annotations: annotations,
		}
	}

	// Flatten embedded structs
	if t, ok := member.Type.(*btf.Struct); ok {
		// Add outer struct as well
		field := newField(t.Size, api.Kind_Bytes)
		newParent := len(*fields)
		*fields = append(*fields, field)

		i.logger.Debugf(" adding field %q (%s) at %d (%v)", prefix+field.name, "struct", field.Offset, tags)
		i.getFieldsFromStruct(t, fields, prefix+member.Name+".", offset+member.Offset.Bytes(), newParent)
		return
	}

	if t, ok := member.Type.(*btf.Union); ok {
		// Add outer struct as well
		field := newField(t.Size, api.Kind_Bytes)
		newParent := len(*fields)
		*fields = append(*fields, field)

		i.logger.Debugf(" adding field %q (%s) at %d", prefix+field.name, "union", field.Offset)
		i.getFieldsFromUnion(t, fields, prefix+member.Name+".", offset+member.Offset.Bytes(), newParent)
		return
	}

	if refType == nil {
		i.logger.Debugf(" skipping field %q (%T)", prefix+member.Name, member.Type)
		return
	}

	fsize := uint32(refType.Size())
	fieldType := refType.String()

	if fsize == 0 {
		i.logger.Debugf(" skipping field %q (%T)", prefix+member.Name, member.Type)
		return
	}

	// Keep enums to convert them to strings
	if en, ok := member.Type.(*btf.Enum); ok {
		i.enums = append(i.enums, &enum{Enum: en, memberName: prefix + member.Name})
	}

	kind := getFieldKind(refType, tags)

	field := newField(fsize, kind)

	i.logger.Debugf(" adding field %q (%s) (kind: %s) at %d (parent %d) (%v)",
		prefix+field.name, fieldType, kind.String(), field.Offset, parent, tags)
	*fields = append(*fields, field)
}

func (i *ebpfInstance) getFieldsFromStruct(btfStruct *btf.Struct, fields *[]*Field, prefix string, offset uint32, parent int) {
	for _, member := range btfStruct.Members {
		i.getFieldsFromMember(member, fields, prefix, offset, parent)
	}
}

func (i *ebpfInstance) getFieldsFromUnion(btfStruct *btf.Union, fields *[]*Field, prefix string, offset uint32, parent int) {
	for _, member := range btfStruct.Members {
		i.getFieldsFromMember(member, fields, prefix, offset, parent)
	}
}
