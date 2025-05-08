// Copyright 2022-2024 The Inspektor Gadget authors
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

package columns

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unsafe"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/ellipsis"
)

const (
	MaxCharsUint8  = 3  // 255
	MaxCharsInt8   = 4  // -128
	MaxCharsUint16 = 5  // 65535
	MaxCharsInt16  = 6  // -32768
	MaxCharsUint32 = 10 // 4294967295
	MaxCharsInt32  = 11 // -2147483648
	MaxCharsUint64 = 20 // 18446744073709551615
	MaxCharsInt64  = 20 // −9223372036854775808
	MaxCharsBool   = 5  // false
	MaxCharsChar   = 1  // 1 character
)

type subField struct {
	index       int     // number of the referenced field inside the struct
	offset      uintptr // offset of the referenced field inside the struct
	parentIsPtr bool    // true, if the referenced field is a member of a pointer type
	isPtr       bool    // true, if the referenced field is a pointer type
}

type Attributes struct {
	// Name of the column; case-insensitive for most use cases; includes inherited prefixes
	Name string `yaml:"name"`
	// Name of the columns without inherited prefixes
	RawName string `yaml:"raw_name"`
	// Alias is an alternative shorter name to be used for header of the column; if not set, the Name will be used
	Alias string `yaml:"alias"`
	// Width to reserve for this column
	Width int `yaml:"width"`
	// MinWidth will be the minimum width this column will be scaled to when using auto-scaling
	MinWidth int `yaml:"min_width"`
	// MaxWidth will be the maximum width this column will be scaled to when using auto-scaling
	MaxWidth int `yaml:"max_width"`
	// Alignment of this column (left or right)
	Alignment Alignment `yaml:"alignment"`
	// Visible defines whether a column is to be shown by default
	Visible bool `yaml:"visible"`
	// GroupType defines the aggregation method used when grouping this column
	GroupType GroupType `yaml:"group_type"`
	// EllipsisType defines how to abbreviate this column if the value needs more space than is available
	EllipsisType ellipsis.EllipsisType `yaml:"ellipsis_type"`
	// FixedWidth forces the Width even when using Auto-Scaling
	FixedWidth bool `yaml:"fixed_width"`
	// Precision defines how many decimals should be shown on float values, default: 2
	Precision int `yaml:"precision"`
	// Hex defines whether the value should be shown as a hexadecimal number
	Hex bool `yaml:"hex"`
	// Description can hold a short description of the field that can be used to aid the user
	Description string `yaml:"description"`
	// Order defines the default order in which columns are shown
	Order int `yaml:"order"`
	// Tags can be used to dynamically include or exclude columns
	Tags []string `yaml:"tags"`
	// Template defines the template that will be used. Non-typed templates will be applied first.
	Template string `yaml:"template"`
}

type Column[T any] struct {
	Attributes
	Extractor func(*T) any // Extractor to be used; this can be defined to transform the output before retrieving the actual value

	explicitName  bool                    // true, if the name has been set explicitly
	offset        uintptr                 // offset to the field (relative to root non-ptr struct)
	getStart      func(*T) unsafe.Pointer // getStarts, if present, should point to the start of the struct to be used
	fieldIndex    int                     // used for the main struct
	subFieldIndex []subField              // used for embedded structs
	kind          reflect.Kind            // cached kind info from reflection
	columnType    reflect.Type            // cached type info from reflection
	rawColumnType reflect.Type            // cached type info from reflection
	useTemplate   bool                    // if a template has been set, this will be true
	template      string                  // defines the template that will be used. Non-typed templates will be applied first.
}

func (ci *Column[T]) GetAttributes() *Attributes {
	return &ci.Attributes
}

func (ci *Column[T]) getWidthFromType() int {
	return GetWidthFromType(ci.kind)
}

func (ci *Column[T]) getWidth(params []string) (int, error) {
	if len(params) == 1 {
		return 0, fmt.Errorf("missing %q value for field %q", params[0], ci.Name)
	}
	if params[1] == "type" {
		// Special case, we get the maximum length this field can have by its type
		w := ci.getWidthFromType()
		if w > 0 {
			return w, nil
		}
		return 0, fmt.Errorf("special value %q used for field %q is only available for integer and bool types", params[1], ci.Name)
	}

	res, err := strconv.Atoi(params[1])
	if err != nil {
		return 0, fmt.Errorf("invalid width %q for field %q: %w", params[1], ci.Name, err)
	}

	return res, nil
}

func (ci *Column[T]) fromTag(tag string) error {
	tagInfo := strings.Split(tag, ",")
	// Don't overwrite the name if it has been already set. This prevents an
	// already computed name (for example, with a prefix) from being overwritten
	// when applying a template.
	if ci.Name == "" {
		ci.Name = tagInfo[0]
		ci.RawName = ci.Name
	}
	if len(ci.Name) > 0 {
		ci.explicitName = true
	}
	return ci.parseTagInfo(tagInfo[1:])
}

func (ci *Column[T]) applyTemplate() error {
	if ci.Template == "" {
		return nil
	}
	name := ci.Name
	tpl, ok := getTemplate(ci.Template)
	if !ok {
		return fmt.Errorf("applying template %q for %q on field %q: template not found", ci.Template, ci.rawColumnType.Name(), name)
	}
	err := ci.parseTagInfo(strings.Split(tpl, ","))
	if err != nil {
		return fmt.Errorf("applying template %q for %q on field %q: %w", ci.Template, ci.rawColumnType.Name(), name, err)
	}
	ci.Name = name
	return nil
}

func (ci *Column[T]) parseTagInfo(tagInfo []string) error {
	var err error
	for _, subTag := range tagInfo {
		params := strings.SplitN(subTag, ":", 2)
		paramsLen := len(params)
		switch params[0] {
		case "align":
			if paramsLen == 1 {
				return fmt.Errorf("missing alignment value for field %q", ci.Name)
			}
			switch params[1] {
			case "left":
				ci.Alignment = AlignLeft
			case "right":
				ci.Alignment = AlignRight
			default:
				return fmt.Errorf("invalid alignment %q for field %q", params[1], ci.Name)
			}
		case "ellipsis":
			if paramsLen == 1 {
				ci.EllipsisType = ellipsis.End
				continue
			}
			switch params[1] {
			case "end", "":
				ci.EllipsisType = ellipsis.End
			case "middle":
				ci.EllipsisType = ellipsis.Middle
			case "none":
				ci.EllipsisType = ellipsis.None
			case "start":
				ci.EllipsisType = ellipsis.Start
			default:
				return fmt.Errorf("invalid ellipsis value %q for field %q", params[1], ci.Name)
			}
		case "hex":
			if paramsLen != 1 {
				return fmt.Errorf("parameter hex on field %q must not have a value", ci.Name)
			}
			ci.Hex = true
		case "fixed":
			if paramsLen != 1 {
				return fmt.Errorf("parameter fixed on field %q must not have a value", ci.Name)
			}
			ci.FixedWidth = true
		case "group":
			if paramsLen == 1 {
				return fmt.Errorf("missing group value for field %q", ci.Name)
			}
			switch params[1] {
			case "sum":
				if !ci.columnType.ConvertibleTo(reflect.TypeOf(int(0))) {
					return fmt.Errorf("invalid use of sum on field %q of kind %q", ci.Name, ci.kind.String())
				}
				ci.GroupType = GroupTypeSum
			default:
				return fmt.Errorf("invalid group value %q for field %q", params[1], ci.Name)
			}
		case "hide":
			if paramsLen != 1 {
				return fmt.Errorf("parameter hide on field %q must not have a value", ci.Name)
			}
			ci.Visible = false
		case "noembed":
			if ci.Kind() != reflect.Struct && (ci.Kind() != reflect.Pointer || ci.Type().Elem().Kind() != reflect.Struct) {
				return fmt.Errorf("parameter noembed on field %q is only valid for struct types", ci.Name)
			}
		case "order":
			if paramsLen == 1 {
				return fmt.Errorf("missing width value for field %q", ci.Name)
			}
			w, err := strconv.Atoi(params[1])
			if err != nil {
				return fmt.Errorf("invalid order value %q for field %q: %w", params[1], ci.Name, err)
			}
			ci.Order = w
		case "precision":
			if ci.kind != reflect.Float32 && ci.kind != reflect.Float64 {
				return fmt.Errorf("field %q is not a float field and thereby cannot have precision defined", ci.Name)
			}
			if paramsLen == 1 {
				return fmt.Errorf("missing precision value for field %q", ci.Name)
			}
			w, err := strconv.Atoi(params[1])
			if err != nil {
				return fmt.Errorf("invalid precision value %q for field %q: %w", params[1], ci.Name, err)
			}
			if w < -1 {
				return fmt.Errorf("negative precision value %q for field %q", params[1], ci.Name)
			}
			ci.Precision = w
		case "width":
			ci.Width, err = ci.getWidth(params)
			if err != nil {
				return err
			}
		case "maxWidth":
			ci.MaxWidth, err = ci.getWidth(params)
			if err != nil {
				return err
			}
		case "minWidth":
			ci.MinWidth, err = ci.getWidth(params)
			if err != nil {
				return err
			}
		case "template":
			ci.useTemplate = true
			if paramsLen < 2 || params[1] == "" {
				return fmt.Errorf("no template specified for field %q", ci.Name)
			}
			ci.Template = params[1]
		case "stringer":
			if ci.Extractor != nil {
				break
			}
			stringer := reflect.TypeOf((*fmt.Stringer)(nil)).Elem()
			if ci.Type().Implements(stringer) {
				ci.Extractor = func(t *T) any {
					return ci.getRawField(reflect.ValueOf(t)).Interface().(fmt.Stringer).String()
				}
				ci.kind = reflect.String
				ci.columnType = stringType
			} else {
				return fmt.Errorf("column parameter %q set for field %q, but doesn't implement fmt.Stringer", params[0], ci.Name)
			}
		default:
			return fmt.Errorf("invalid column parameter %q for field %q", params[0], ci.Name)
		}
	}
	return nil
}

// Get returns the reflected value of an entry for the current column; if given nil, it will return the zero value of
// the underlying type
func (ci *Column[T]) Get(entry *T) reflect.Value {
	if entry == nil {
		return reflect.Zero(ci.Type())
	}
	v := reflect.ValueOf(entry)
	if ci.Extractor != nil {
		return reflect.ValueOf(ci.Extractor(v.Interface().(*T)))
	}
	return ci.getRawField(v)
}

func (ci *Column[T]) getOffset() uintptr {
	return ci.offset
}

func (ci *Column[T]) getSubFields() []subField {
	return ci.subFieldIndex
}

// GetRef returns the reflected value of an already reflected entry for the current column; expects v to be valid or
// will panic
func (ci *Column[T]) GetRef(v reflect.Value) reflect.Value {
	if ci.Extractor != nil || ci.fieldIndex == manualIndex {
		return reflect.ValueOf(ci.Extractor(v.Interface().(*T)))
	}
	return ci.getRawField(v)
}

// GetRaw returns the reflected value of an entry for the current column without evaluating the extractor func;
// if given nil or run on a virtual or manually added column, it will return the zero value of the underlying type.
// If using embedded structs via pointers and the embedded value is nil, it will also return the zero value of the
// underlying type.
func (ci *Column[T]) GetRaw(entry *T) reflect.Value {
	if entry == nil || ci.fieldIndex == virtualIndex || ci.fieldIndex == manualIndex {
		return reflect.Zero(ci.RawType())
	}
	v := reflect.ValueOf(entry)
	return ci.getRawField(v)
}

func (ci *Column[T]) getRawField(v reflect.Value) reflect.Value {
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if len(ci.subFieldIndex) > 0 {
		return ci.getFieldRec(v, ci.subFieldIndex)
	}
	return v.Field(ci.fieldIndex)
}

func (ci *Column[T]) getFieldRec(v reflect.Value, sub []subField) reflect.Value {
	if sub[0].parentIsPtr {
		if v.IsNil() {
			// Return the (empty) default value for this type
			return reflect.Zero(ci.Type())
		}
		v = v.Elem()
	}
	val := v.Field(sub[0].index)
	if len(sub) == 1 {
		return val
	}
	return ci.getFieldRec(val, sub[1:])
}

// Kind returns the underlying kind of the column (always reflect.String in case of virtual columns)
func (ci *Column[T]) Kind() reflect.Kind {
	return ci.kind
}

// Type returns the underlying type of the column
// (reflect.String, if a custom extractor is used)
func (ci *Column[T]) Type() reflect.Type {
	return ci.columnType
}

// RawType returns the underlying type of the column
func (ci *Column[T]) RawType() reflect.Type {
	return ci.rawColumnType
}

func (ci *Column[T]) HasTag(tag string) bool {
	for _, curTag := range ci.Tags {
		if curTag == tag {
			return true
		}
	}
	return false
}

func (ci *Column[T]) HasNoTags() bool {
	return len(ci.Tags) == 0
}

// IsEmbedded returns true, if the current column is a member of an embedded struct
func (ci *Column[T]) IsEmbedded() bool {
	return len(ci.subFieldIndex) != 0
}

// IsVirtual returns true, if the column has direct reference to a field
func (ci *Column[T]) IsVirtual() bool {
	return ci.fieldIndex == virtualIndex
}

// HasCustomExtractor returns true, if the column has a user defined extractor set
func (ci *Column[T]) HasCustomExtractor() bool {
	return ci.Extractor != nil
}
