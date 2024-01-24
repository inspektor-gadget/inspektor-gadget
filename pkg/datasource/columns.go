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
	"unsafe"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/formatter/json"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
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

func (ds *dataSource) JSONFormatter() (*json.Formatter[DataTuple], error) {
	cols, err := ds.Columns()
	if err != nil {
		return nil, fmt.Errorf("creating columns: %w", err)
	}
	formatter := json.NewFormatter(cols.GetColumnMap())
	return formatter, nil
}

func (ds *dataSource) Columns() (*columns.Columns[DataTuple], error) {
	cols, err := columns.NewColumns[DataTuple]()
	if err != nil {
		return nil, err
	}

	for _, f := range ds.fields {
		if FieldFlagEmpty.In(f.Flags) {
			continue
		}
		if f.ReflectType() == nil {
			// if f.Size > 0 {
			// 	// Unsupported
			// 	continue
			// }
			df := columns.DynamicField{
				Attributes: &columns.Attributes{
					Name:    f.Name,
					Tags:    f.Tags,
					Visible: !FieldFlagHidden.In(f.Flags),
					Width:   columns.GetDefault().DefaultWidth,
				},
				Tag:      "",
				Template: "",
				Type:     reflect.TypeOf([]byte{}),
				Offset:   uintptr(f.Offs),
			}

			acc := &fieldAccessor{
				ds: ds,
				f:  f,
			}
			fromC := slices.Contains(f.Tags, "src:ebpf") // TODO: Const + doc
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
		df := columns.DynamicField{
			Attributes: &columns.Attributes{
				Name:    f.Name,
				Tags:    f.Tags,
				Visible: !FieldFlagHidden.In(f.Flags),
				Width:   columns.GetWidthFromType(f.ReflectType().Kind()),
			},
			Tag:      "",
			Template: "",
			Type:     f.ReflectType(),
			Offset:   uintptr(f.Offs),
		}
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
