// Copyright 2022 The Inspektor Gadget authors
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
)

type Column[T any] struct {
	Name         string                // Name of the column; case-insensitive for most use cases
	Width        int                   // Width to reserve for this column
	MinWidth     int                   // MinWidth will be the minimum width this column will be scaled to when using auto-scaling
	MaxWidth     int                   // MaxWidth will be the maximum width this column will be scaled to when using auto-scaling
	Alignment    Alignment             // Alignment of this column (left or right)
	Extractor    func(*T) string       // Extractor to be used; this can be defined to transform the output before retrieving the actual value
	Visible      bool                  // Visible defines whether a column is to be shown by default
	GroupType    GroupType             // GroupType defines the aggregation method used when grouping this column
	EllipsisType ellipsis.EllipsisType // EllipsisType defines how to abbreviate this column if the value needs more space than is available
	FixedWidth   bool                  // FixedWidth forces the Width even when using Auto-Scaling
	Precision    int                   // Precision defines how many decimals should be shown on float values, default: 2
	Description  string                // Description can hold a short description of the field that can be used to aid the user
	Order        int                   // Order defines the default order in which columns are shown
	Tags         []string              // Tags can be used to dynamically include or exclude columns

	fieldIndex    int          // used for the main struct
	subFieldIndex []int        // used for embedded structs
	kind          reflect.Kind // cached kind info from reflection
	columnType    reflect.Type // cached type info from reflection
}

func (ci *Column[T]) getWidthFromType() int {
	switch ci.kind {
	case reflect.Uint8:
		return MaxCharsUint8
	case reflect.Int8:
		return MaxCharsInt8
	case reflect.Uint16:
		return MaxCharsUint16
	case reflect.Int16:
		return MaxCharsInt16
	case reflect.Uint32:
		return MaxCharsUint32
	case reflect.Int32:
		return MaxCharsInt32
	case reflect.Uint64, reflect.Uint:
		return MaxCharsUint64
	case reflect.Int64, reflect.Int:
		return MaxCharsInt64
	case reflect.Bool:
		return MaxCharsBool
	}
	return 0
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
	ci.Name = tagInfo[0]

	tagInfo = tagInfo[1:]
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
					return fmt.Errorf("cannot use sum on field %q of kind %q", ci.Name, ci.kind.String())
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

// GetRef returns the reflected value of an already reflected entry for the current column; expects v to be valid or
// will panic
func (ci *Column[T]) GetRef(v reflect.Value) reflect.Value {
	if ci.Extractor != nil {
		return reflect.ValueOf(ci.Extractor(v.Interface().(*T)))
	}
	return ci.getRawField(v)
}

// GetRaw returns the reflected value of an entry for the current column without evaluating the extractor func;
// if given nil or run on a virtual column, it will return the zero value of the underlying type
func (ci *Column[T]) GetRaw(entry *T) reflect.Value {
	if entry == nil || ci.fieldIndex == virtualIndex {
		return reflect.Zero(ci.Type())
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

func (ci *Column[T]) getFieldRec(v reflect.Value, sub []int) reflect.Value {
	val := v.Field(sub[0])
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
func (ci *Column[T]) Type() reflect.Type {
	return ci.columnType
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
	if len(ci.Tags) == 0 {
		return true
	}
	return false
}

// IsEmbedded returns true, if the current column is a member of an embedded struct
func (ci *Column[T]) IsEmbedded() bool {
	if len(ci.subFieldIndex) == 0 {
		return false
	}
	return true
}
