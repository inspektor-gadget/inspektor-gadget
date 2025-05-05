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

package sort

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	name        = "sort"
	ParamSortBy = "sort"
	Priority    = 9500
)

type sortOperator struct{}

type arrSort struct {
	datasource.DataArray
	fn func(i, j datasource.Data) bool
}

func (s *arrSort) Less(i, j int) bool {
	return s.fn(s.Get(i), s.Get(j))
}

func (s *sortOperator) Name() string {
	return name
}

func (s *sortOperator) Init(params *params.Params) error {
	return nil
}

func (s *sortOperator) GlobalParams() api.Params {
	return nil
}

func (s *sortOperator) InstanceParams() api.Params {
	return api.Params{
		{
			Key:   ParamSortBy,
			Title: "Sort By",
			Description: "Sort by fields. Join multiple fields with ','. Prefix a field with '-' to sort in descending order. " +
				"If using multiple data sources, prefix fields with 'datasourcename:' and separate with ';'",
		},
	}
}

func (s *sortOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	activate := false

	sortBy := instanceParamValues[ParamSortBy]

	for _, ds := range gadgetCtx.GetDataSources() {
		if ds.Type() == datasource.TypeArray {
			activate = true
			break
		}
	}

	if !activate {
		return nil, nil
	}

	return &sortOperatorInstance{
		sortBy: sortBy,
	}, nil
}

func (s *sortOperator) Priority() int {
	return Priority
}

type sortOperatorInstance struct {
	sortBy  string
	sorters map[datasource.DataSource][]func(i, j datasource.Data) bool
}

func getCompareFunc(f datasource.FieldAccessor, negate bool) func(i, j datasource.Data) bool {
	switch f.Type() {
	case api.Kind_Int8:
		return func(i, j datasource.Data) bool {
			v1, _ := f.Int8(i)
			v2, _ := f.Int8(j)
			return (v1 < v2) != negate
		}
	case api.Kind_Int16:
		return func(i, j datasource.Data) bool {
			v1, _ := f.Int16(i)
			v2, _ := f.Int16(j)
			return (v1 < v2) != negate
		}
	case api.Kind_Int32:
		return func(i, j datasource.Data) bool {
			v1, _ := f.Int32(i)
			v2, _ := f.Int32(j)
			return (v1 < v2) != negate
		}
	case api.Kind_Int64:
		return func(i, j datasource.Data) bool {
			v1, _ := f.Int64(i)
			v2, _ := f.Int64(j)
			return (v1 < v2) != negate
		}
	case api.Kind_Uint8:
		return func(i, j datasource.Data) bool {
			v1, _ := f.Uint8(i)
			v2, _ := f.Uint8(j)
			return (v1 < v2) != negate
		}
	case api.Kind_Uint16:
		return func(i, j datasource.Data) bool {
			v1, _ := f.Uint16(i)
			v2, _ := f.Uint16(j)
			return (v1 < v2) != negate
		}
	case api.Kind_Uint32:
		return func(i, j datasource.Data) bool {
			v1, _ := f.Uint32(i)
			v2, _ := f.Uint32(j)
			return (v1 < v2) != negate
		}
	case api.Kind_Uint64:
		return func(i, j datasource.Data) bool {
			v1, _ := f.Uint64(i)
			v2, _ := f.Uint64(j)
			return (v1 < v2) != negate
		}
	case api.Kind_Float32:
		return func(i, j datasource.Data) bool {
			v1, _ := f.Float32(i)
			v2, _ := f.Float32(j)
			return (v1 < v2) != negate
		}
	case api.Kind_Float64:
		return func(i, j datasource.Data) bool {
			v1, _ := f.Float64(i)
			v2, _ := f.Float64(j)
			return (v1 < v2) != negate
		}
	case api.Kind_String, api.Kind_CString:
		return func(i, j datasource.Data) bool {
			v1, _ := f.String(i)
			v2, _ := f.String(j)
			if strings.Compare(v1, v2) < 0 {
				return !negate
			}
			return negate
		}
	default:
		return nil
	}
}

func (s *sortOperatorInstance) init(gadgetCtx operators.GadgetContext) error {
	s.sorters = make(map[datasource.DataSource][]func(i datasource.Data, j datasource.Data) bool)
	dsSorts := make(map[string][]string)
	for _, srt := range strings.Split(s.sortBy, ";") {
		dsFields := strings.Split(srt, ":")
		dsName := ""
		fieldList := dsFields[0]
		if len(dsFields) == 2 {
			dsName = dsFields[0]
			fieldList = dsFields[1]
		}
		fields := strings.Split(fieldList, ",")
		if len(fields) > 2 || fields[0] != "" {
			dsSorts[dsName] = fields
		}
	}

	// Check edge cases
	dsSpecific := true
	if _, ok := dsSorts[""]; ok {
		if len(dsSorts) > 1 {
			return fmt.Errorf("mixing sorting rules with and without specifying data source")
		}
		dsSpecific = false
	}

	for _, ds := range gadgetCtx.GetDataSources() {
		sortFields := dsSorts[ds.Name()]
		if !dsSpecific {
			sortFields = dsSorts[""]
		}

		if len(sortFields) == 0 {
			continue
		}

		if ds.Type() != datasource.TypeArray {
			return fmt.Errorf("sort can only be used on array data sources")
		}

		var sortFuncs []func(i, j datasource.Data) bool
		for _, fieldName := range sortFields {
			fieldName, negate := strings.CutPrefix(fieldName, "-")

			field := ds.GetField(fieldName)
			if field == nil {
				return fmt.Errorf("field %s not found", fieldName)
			}

			cmp := getCompareFunc(field, negate)
			if cmp == nil {
				return fmt.Errorf("field %s cannot be used for sorting", fieldName)
			}
			sortFuncs = append(sortFuncs, cmp)
		}

		slices.Reverse(sortFuncs)
		s.sorters[ds] = sortFuncs
	}
	return nil
}

func (s *sortOperatorInstance) Name() string {
	return name
}

func (s *sortOperatorInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	err := s.init(gadgetCtx)
	if err != nil {
		return err
	}
	for ds, fns := range s.sorters {
		ds.SubscribeArray(func(ds datasource.DataSource, data datasource.DataArray) error {
			for _, s := range fns {
				sort.Stable(&arrSort{DataArray: data, fn: s})
			}
			return nil
		}, Priority)
	}
	return nil
}

func (s *sortOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (s *sortOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

var Operator = &sortOperator{}

func init() {
	operators.RegisterDataOperator(Operator)
}
