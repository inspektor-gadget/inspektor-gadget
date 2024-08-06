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
	"strconv"
	"unsafe"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/ellipsis"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	metadatav1 "github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

const (
	// ColumnsReplaceAnnotation is used to indicate that this field should be
	// replaced by the one indicated in the annotation when printing it.
	ColumnsReplaceAnnotation = "columns.replace"

	ColumnsWidthAnnotation     = "columns.width"
	ColumnsMaxWidthAnnotation  = "columns.maxwidth"
	ColumnsMinWidthAnnotation  = "columns.minwidth"
	ColumnsAlignmentAnnotation = "columns.alignment"
	ColumnsEllipsisAnnotation  = "columns.ellipsis"
	ColumnsHiddenAnnotation    = "columns.hidden"
	ColumnsFixedAnnotation     = "columns.fixed"
	ColumnsHexAnnotation       = "columns.hex"

	DescriptionAnnotation = "description"
	TemplateAnnotation    = "template"
)

type DataTuple struct {
	ds   DataSource
	data Data
}

func NewDataTuple(ds DataSource, d Data) *DataTuple {
	return &DataTuple{
		ds:   ds,
		data: d,
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
			case ColumnsAlignmentAnnotation:
				switch metadatav1.Alignment(v) {
				case metadatav1.AlignmentLeft:
					attributes.Alignment = columns.AlignLeft
				case metadatav1.AlignmentRight:
					attributes.Alignment = columns.AlignRight
				default:
					return nil, fmt.Errorf("invalid alignment type for column %q: %s", f.Name, v)
				}
			case ColumnsEllipsisAnnotation:
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
			case ColumnsWidthAnnotation:
				var err error
				attributes.Width, err = strconv.Atoi(v)
				if err != nil {
					return nil, fmt.Errorf("reading width for column %q: %w", f.Name, err)
				}
			case ColumnsMinWidthAnnotation:
				var err error
				attributes.MinWidth, err = strconv.Atoi(v)
				if err != nil {
					return nil, fmt.Errorf("reading minWidth for column %q: %w", f.Name, err)
				}
			case ColumnsMaxWidthAnnotation:
				var err error
				attributes.MaxWidth, err = strconv.Atoi(v)
				if err != nil {
					return nil, fmt.Errorf("reading maxWidth for column %q: %w", f.Name, err)
				}
			case ColumnsFixedAnnotation:
				if v == "true" {
					attributes.FixedWidth = true
				}
			case ColumnsHexAnnotation:
				if v == "true" {
					attributes.Hex = true
				}
			}
		}

		// Use replace field if it's defined
		if replacementField, ok := f.Annotations[ColumnsReplaceAnnotation]; ok {
			f, ok = ds.fieldMap[replacementField]
			if !ok {
				return nil, fmt.Errorf("replacement field %q not found", replacementField)
			}
		}

		if f.Kind == api.Kind_CString || f.Kind == api.Kind_String {
			acc := &fieldAccessor{
				ds: ds,
				f:  f,
			}

			err := cols.AddColumn(*df.Attributes, func(d *DataTuple) any {
				if d.data == nil {
					return ""
				}
				str, _ := acc.String(d.data)
				return str
			})
			if err != nil {
				return nil, fmt.Errorf("creating columns: %w", err)
			}

			continue
		}

		if f.ReflectType() == nil {
			df.Type = reflect.TypeOf([]byte{})

			acc := &fieldAccessor{
				ds: ds,
				f:  f,
			}
			err := cols.AddColumn(*df.Attributes, func(d *DataTuple) any {
				if d.data == nil {
					return ""
				}
				data := acc.Get(d.data)
				return fmt.Sprintf("<%d bytes>", len(data))
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
			if len(d.data.payload()[idx]) == 0 {
				return nil
			}
			return unsafe.Pointer(&d.data.payload()[idx][0])
		})
		if err != nil {
			return nil, fmt.Errorf("creating columns: %w", err)
		}
	}
	return cols, nil
}

var defaultFieldAnnotations = map[string]string{
	ColumnsWidthAnnotation:     "16",
	ColumnsEllipsisAnnotation:  string(metadatav1.EllipsisEnd),
	ColumnsAlignmentAnnotation: string(metadatav1.AlignmentLeft),
}

var annotationsTemplates = map[string]map[string]string{
	"timestamp": {
		ColumnsWidthAnnotation:    "35",
		ColumnsMaxWidthAnnotation: "35",
		ColumnsEllipsisAnnotation: "end",
	},
	"node": {
		ColumnsWidthAnnotation:    "30",
		ColumnsEllipsisAnnotation: string(metadatav1.EllipsisMiddle),
	},
	"pod": {
		ColumnsWidthAnnotation:    "30",
		ColumnsEllipsisAnnotation: string(metadatav1.EllipsisMiddle),
	},
	"container": {
		ColumnsWidthAnnotation: "30",
	},
	"namespace": {
		ColumnsWidthAnnotation: "30",
	},
	"containerImageName": {
		ColumnsWidthAnnotation: "30",
	},
	"containerImageDigest": {
		ColumnsWidthAnnotation: "30",
	},
	"containerStartedAt": {
		ColumnsHiddenAnnotation: "true",
		ColumnsWidthAnnotation:  "35",
	},
	"comm": {
		DescriptionAnnotation:     "Process name",
		ColumnsMaxWidthAnnotation: "16",
	},
	"pcomm": {
		DescriptionAnnotation:     "The process name of the parent process",
		ColumnsMaxWidthAnnotation: "16",
	},
	"pid": {
		ColumnsMinWidthAnnotation:  "7",
		ColumnsAlignmentAnnotation: string(metadatav1.AlignmentRight),
	},
	"uid": {
		ColumnsMinWidthAnnotation:  "8",
		ColumnsAlignmentAnnotation: string(metadatav1.AlignmentRight),
	},
	"gid": {
		ColumnsMinWidthAnnotation:  "8",
		ColumnsAlignmentAnnotation: string(metadatav1.AlignmentRight),
	},
	"ns": {
		ColumnsHiddenAnnotation:    "true",
		ColumnsWidthAnnotation:     "12",
		ColumnsAlignmentAnnotation: string(metadatav1.AlignmentRight),
	},
	"l4endpoint": {
		ColumnsMinWidthAnnotation: "22",
		ColumnsWidthAnnotation:    "40",
		ColumnsMaxWidthAnnotation: "52",
	},
	"syscall": {
		ColumnsWidthAnnotation:    "18",
		ColumnsMaxWidthAnnotation: "28",
	},
	"errorString": {
		ColumnsWidthAnnotation: "12",
	},
}
