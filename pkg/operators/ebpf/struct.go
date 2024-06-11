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
	"fmt"
	"reflect"
	"slices"

	"github.com/cilium/ebpf/btf"
	"gopkg.in/yaml.v3"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/btfhelpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	metadatav1 "github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1"
)

type Field struct {
	metadatav1.Field
	Tags   []string
	Offset uint32
	Size   uint32
	parent int
	name   string
	kind   api.Kind
}

type Struct struct {
	Fields []*Field `yaml:"fields"`
	Size   uint32
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

func (f *Field) FieldHidden() bool {
	return f.Attributes.Hidden
}

func (f *Field) FieldAnnotations() map[string]string {
	out := make(map[string]string)

	for k, v := range f.Annotations {
		if s, ok := v.(string); ok {
			out[k] = s
		} else {
			// try to copy rest
			out[k] = fmt.Sprintf("%v", v)
		}
	}

	if val := f.Description; val != "" {
		out["description"] = val
	}

	// Rewrite attributes as annotations; TODO: tbd
	if val := f.Attributes.Alignment; val != "" {
		out["columns.alignment"] = string(val)
	}
	if val := f.Attributes.Ellipsis; val != "" {
		out["columns.ellipsis"] = string(val)
	}
	if val := f.Attributes.Width; val != 0 {
		out["columns.width"] = fmt.Sprintf("%d", val)
	}
	if val := f.Attributes.MinWidth; val != 0 {
		out["columns.minWidth"] = fmt.Sprintf("%d", val)
	}
	if val := f.Attributes.MaxWidth; val != 0 {
		out["columns.maxWidth"] = fmt.Sprintf("%d", val)
	}
	if val := f.Attributes.Template; val != "" {
		out["columns.template"] = val
	}
	if val := f.Attributes.Hidden; val {
		out["hidden"] = "true"
	}
	return out
}

func (f *Field) FieldParent() int {
	return f.parent
}

func (i *ebpfInstance) populateStructDirect(btfStruct *btf.Struct) error {
	gadgetStruct := i.structs[btfStruct.Name]
	existingFields := make(map[string]*Field)

	if gadgetStruct == nil {
		gadgetStruct = &Struct{}
		i.logger.Debugf("adding struct %q", btfStruct.Name)
	}

	// TODO: make this validate the struct
	for _, field := range gadgetStruct.Fields {
		existingFields[field.Name] = field
	}

	i.getFieldsFromStruct(btfStruct, &gadgetStruct.Fields, "", 0, -1)

	var configStruct *metadatav1.Struct
	fields := i.config.Sub("structs." + btfStruct.Name)
	if fields != nil {
		// This feels ugly, maybe optimize
		d, _ := yaml.Marshal(fields.AllSettings())
		err := yaml.Unmarshal(d, &configStruct)
		if err != nil {
			return fmt.Errorf("invalid metadata for struct %q", btfStruct.Name)
		}

		// Build lookup
		lookup := make(map[string]metadatav1.Field)
		for _, field := range configStruct.Fields {
			lookup[field.Name] = field
		}

		// Only handling topmost layer for now // TODO
		for _, field := range gadgetStruct.Fields {
			cfgField, ok := lookup[field.Name]
			if !ok {
				continue
			}
			i.logger.Debugf(" found field config for %q", field.Name)

			// Fill in blanks from metadata
			field.Description = cfgField.Description
			field.Attributes = cfgField.Attributes
			field.Annotations = cfgField.Annotations
		}
	}

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
	}

	return api.Kind_Invalid
}

func (i *ebpfInstance) getFieldsFromMember(member btf.Member, fields *[]*Field, prefix string, offset uint32, parent int) {
	refType, tags := btfhelpers.GetType(member.Type)
	for i := range tags {
		tags[i] = "type:" + tags[i]
	}

	tags = append(tags, "name:"+member.Name, api.TagSrcEbpf)

	defaultAttributes := metadatav1.FieldAttributes{
		Alignment: metadatav1.AlignmentLeft,
		Ellipsis:  metadatav1.EllipsisEnd,
	}

	newField := func(size uint32, kind api.Kind) *Field {
		return &Field{
			Field: metadatav1.Field{
				Name:       prefix + member.Name,
				Attributes: defaultAttributes,
			},
			Size:   size,
			Tags:   tags,
			Offset: offset + member.Offset.Bytes(),
			parent: parent,
			name:   member.Name,
			kind:   kind,
		}
	}

	// Flatten embedded structs
	if t, ok := member.Type.(*btf.Struct); ok {
		// Add outer struct as well
		field := newField(t.Size, api.Kind_Bytes)
		newParent := len(*fields)
		*fields = append(*fields, field)

		i.logger.Debugf(" adding field %q (%s) at %d (%v)", field.Name, "struct", field.Offset, tags)
		i.getFieldsFromStruct(t, fields, prefix+member.Name+".", offset+member.Offset.Bytes(), newParent)
		return
	}

	if t, ok := member.Type.(*btf.Union); ok {
		// Add outer struct as well
		field := newField(t.Size, api.Kind_Bytes)
		newParent := len(*fields)
		*fields = append(*fields, field)

		i.logger.Debugf(" adding field %q (%s) at %d", field.Name, "union", field.Offset)
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
	if enum, ok := member.Type.(*btf.Enum); ok {
		i.enums[member.Name] = enum
	}

	kind := getFieldKind(refType, tags)

	field := newField(fsize, kind)
	field.Field.Attributes.Width = uint(columns.GetWidthFromType(refType.Kind()))

	i.logger.Debugf(" adding field %q (%s) (kind: %s) at %d (parent %d) (%v)",
		field.Name, fieldType, kind.String(), field.Offset, parent, tags)
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
