// Copyright 2022-2023 The Inspektor Gadget authors
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
	"reflect"
	"sort"

	"golang.org/x/exp/constraints"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
)

type columnSorter[T any] struct {
	column *columns.Column[T]
	order  columns.Order
}

type ColumnSorterCollection[T any] struct {
	sorters []*columnSorter[T]
}

func (csc *ColumnSorterCollection[T]) Sort(entries []*T) {
	if len(entries) == 0 {
		return
	}

	for _, s := range csc.sorters {
		var sortFunc func(i, j int) bool
		order := s.order

		kind := s.column.Kind()
		if s.column.HasCustomExtractor() {
			kind = s.column.GetRaw(entries[0]).Kind()
		}

		switch kind {
		case reflect.Int:
			sortFunc = getLessFunc[int, T](entries, s.column, order)
		case reflect.Int8:
			sortFunc = getLessFunc[int8, T](entries, s.column, order)
		case reflect.Int16:
			sortFunc = getLessFunc[int16, T](entries, s.column, order)
		case reflect.Int32:
			sortFunc = getLessFunc[int32, T](entries, s.column, order)
		case reflect.Int64:
			sortFunc = getLessFunc[int64, T](entries, s.column, order)
		case reflect.Uint:
			sortFunc = getLessFunc[uint, T](entries, s.column, order)
		case reflect.Uint8:
			sortFunc = getLessFunc[uint8, T](entries, s.column, order)
		case reflect.Uint16:
			sortFunc = getLessFunc[uint16, T](entries, s.column, order)
		case reflect.Uint32:
			sortFunc = getLessFunc[uint32, T](entries, s.column, order)
		case reflect.Uint64:
			sortFunc = getLessFunc[uint64, T](entries, s.column, order)
		case reflect.Float32:
			sortFunc = getLessFunc[float32, T](entries, s.column, order)
		case reflect.Float64:
			sortFunc = getLessFunc[float64, T](entries, s.column, order)
		case reflect.String:
			sortFunc = getLessFunc[string, T](entries, s.column, order)
		default:
			continue
		}

		sort.SliceStable(entries, sortFunc)
	}
}

// Prepare prepares a sorter collection that can be re-used for multiple calls to Sort() for efficiency. Filter rules
// will be applied from right to left (first rule has the highest priority).
func Prepare[T any](cols columns.ColumnMap[T], sortBy []string) *ColumnSorterCollection[T] {
	valid, _ := FilterSortableColumns(cols, sortBy)

	sorters := make([]*columnSorter[T], 0, len(sortBy))
	for i := len(valid) - 1; i >= 0; i-- {
		sortField := valid[i]
		// Handle ordering
		order := columns.OrderAsc
		if sortField[0] == '-' {
			sortField = sortField[1:]
			order = columns.OrderDesc
		}

		column, _ := cols.GetColumn(sortField)

		sorters = append(sorters, &columnSorter[T]{
			column: column,
			order:  order,
		})
	}

	return &ColumnSorterCollection[T]{
		sorters: sorters,
	}
}

// SortEntries sorts entries by applying the sortBy rules from right to left (first rule has the highest
// priority). The rules are strings containing the column names, optionally prefixed with "-" to switch to descending
// sort order.
func SortEntries[T any](cols columns.ColumnMap[T], entries []*T, sortBy []string) {
	if entries == nil {
		return
	}

	coll := Prepare(cols, sortBy)
	coll.Sort(entries)
}

func getLessFunc[OT constraints.Ordered, T any](array []*T, column columns.ColumnInternals, order columns.Order) func(i, j int) bool {
	fieldFunc := columns.GetFieldFuncExt[OT, T](column, true)
	return func(i, j int) bool {
		if array[i] == nil {
			return false
		}
		if array[j] == nil {
			return true
		}
		return (fieldFunc(array[i]) >= fieldFunc(array[j])) != order
	}
}

// CanSortBy returns true, if all requested sortBy arguments can be used for sorting
// This is not the case for a virtual column, which has no underlying value type
func CanSortBy[T any](cols columns.ColumnMap[T], sortBy []string) bool {
	valid, _ := FilterSortableColumns(cols, sortBy)

	return len(valid) == len(sortBy)
}

// FilterSortableColumns returns two lists, one containing the valid column names
// and another containing the invalid column names.
func FilterSortableColumns[T any](cols columns.ColumnMap[T], sortBy []string) ([]string, []string) {
	valid := make([]string, 0, len(sortBy))
	invalid := make([]string, 0)

	for _, sortField := range sortBy {
		if len(sortField) == 0 {
			invalid = append(invalid, sortField)
			continue
		}

		rawSortField := sortField
		if rawSortField[0] == '-' {
			rawSortField = rawSortField[1:]
		}

		column, ok := cols.GetColumn(rawSortField)
		if !ok {
			invalid = append(invalid, sortField)
			continue
		}

		// Skip virtual columns, they have no underlying value to sort by
		if column.IsVirtual() {
			invalid = append(invalid, sortField)
			continue
		}

		valid = append(valid, sortField)
	}

	return valid, invalid
}
