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
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"unsafe"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/ellipsis"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	metadatav1 "github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

type DataTuple struct {
	ds   DataSource
	data *data
}

func NewDataTuple(ds DataSource, d Data) *DataTuple {
	return &DataTuple{
		ds:   ds,
		data: d.(*data),
	}
}

func (ds *dataSource) Parser() (parser.Parser, error) {
	cols, err := ds.Columns()
	if err != nil {
		return nil, err
	}
	return parser.NewParser(cols), nil
}

func (ds *dataSource) Columns() (*columns.Columns[DataTuple], error) {
	cols, err := columns.NewColumns[DataTuple]()
	if err != nil {
		return nil, err
	}

	for i, f := range ds.fields {
		if FieldFlagEmpty.In(f.Flags) || FieldFlagUnreferenced.In(f.Flags) {
			continue
		}

		attributes := &columns.Attributes{
			Name:    f.FullName,
			Tags:    f.Tags,
			Visible: !FieldFlagHidden.In(f.Flags),
			Width:   columns.GetDefault().DefaultWidth,
			Order:   i * 100,
		}

		df := columns.DynamicField{
			Attributes: attributes,
			Offset:     uintptr(f.Offs),
		}

		// extract attributes from annotations
		for k, v := range f.Annotations {
			switch k {
			case "columns.alignment":
				switch metadatav1.Alignment(v) {
				case metadatav1.AlignmentLeft:
					attributes.Alignment = columns.AlignLeft
				case metadatav1.AlignmentRight:
					attributes.Alignment = columns.AlignRight
				default:
					return nil, fmt.Errorf("invalid alignment type for column %q: %s", f.Name, v)
				}
			case "columns.ellipsis":
				switch metadatav1.EllipsisType(v) {
				case metadatav1.EllipsisNone:
					attributes.EllipsisType = ellipsis.None
				case metadatav1.EllipsisStart:
					attributes.EllipsisType = ellipsis.Start
				case metadatav1.EllipsisMiddle:
					attributes.EllipsisType = ellipsis.Middle
				case metadatav1.EllipsisEnd:
					attributes.EllipsisType = ellipsis.End
				default:
					return nil, fmt.Errorf("invalid ellipsis type for column %q: %s", f.Name, v)
				}
			case "columns.width":
				var err error
				attributes.Width, err = strconv.Atoi(v)
				if err != nil {
					return nil, fmt.Errorf("reading width for column %q: %w", f.Name, err)
				}
			case "columns.minWidth":
				var err error
				attributes.MinWidth, err = strconv.Atoi(v)
				if err != nil {
					return nil, fmt.Errorf("reading minWidth for column %q: %w", f.Name, err)
				}
			case "columns.maxWidth":
				var err error
				attributes.MaxWidth, err = strconv.Atoi(v)
				if err != nil {
					return nil, fmt.Errorf("reading maxWidth for column %q: %w", f.Name, err)
				}
			case "columns.template":
				attributes.Template = v
				df.Template = v
			case "columns.fixed":
				if v == "true" {
					attributes.FixedWidth = true
				}
			}
		}

		if f.ReflectType() == nil {
			df.Type = reflect.TypeOf([]byte{})

			acc := &fieldAccessor{
				ds: ds,
				f:  f,
			}
			fromC := slices.Contains(f.Tags, api.TagSrcEbpf)
			err := cols.AddColumn(*df.Attributes, func(d *DataTuple) any {
				if d.data == nil {
					return ""
				}

				if fromC {
					return gadgets.FromCString(acc.Get(d.data))
				}
				return string(acc.Get(d.data))
			})
			if err != nil {
				return nil, fmt.Errorf("creating columns: %w", err)
			}
			continue
		}

		if attributes.Width == 0 {
			attributes.Width = columns.GetWidthFromType(f.ReflectType().Kind())
		}

		df.Type = f.ReflectType()
		idx := f.PayloadIndex

		err := cols.AddFields([]columns.DynamicField{df}, func(d *DataTuple) unsafe.Pointer {
			if len(d.data.Payload[idx]) == 0 {
				return nil
			}
			return unsafe.Pointer(&d.data.Payload[idx][0])
		})
		if err != nil {
			return nil, fmt.Errorf("creating columns: %w", err)
		}
	}
	return cols, nil
}
