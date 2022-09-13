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

package sort

import (
	"reflect"
	"sort"

	"github.com/kinvolk/inspektor-gadget/pkg/columns"
)

type columnSorter[T any] struct {
	array   []*T
	column  *columns.Column[T]
	swapper func(i, j int)
	less    func(i, j int) bool
}

// SortEntries sorts entries by applying the sortBy rules from right to left (first rule has the highest
// priority). The rules are strings containing the column names, optionally prefixed with "-" to switch to descending
// sort order.
func SortEntries[T any](cols columns.ColumnMap[T], entries []*T, sortBy []string) {
	if entries == nil {
		return
	}

	for i := len(sortBy) - 1; i >= 0; i-- {
		sortField := sortBy[i]

		if len(sortField) == 0 {
			continue
		}

		// Handle ordering
		order := columns.OrderAsc
		if sortField[0] == '-' {
			sortField = sortField[1:]
			order = columns.OrderDesc
		}

		column, ok := cols.GetColumn(sortField)
		if !ok {
			continue
		}

		sorter := newColumnSorter(entries, column, order)
		if sorter == nil {
			continue
		}
		sort.Stable(sorter)
	}
}

func newColumnSorter[T any](array []*T, column *columns.Column[T], order columns.Order) *columnSorter[T] {
	cs := &columnSorter[T]{
		array:   array,
		column:  column,
		swapper: reflect.Swapper(array),
	}

	switch column.Kind() {
	case reflect.Int,
		reflect.Int8,
		reflect.Int16,
		reflect.Int32,
		reflect.Int64:
		cs.less = func(i, j int) bool {
			v1 := reflect.ValueOf(array[i])
			v2 := reflect.ValueOf(array[j])
			if v1.IsNil() {
				return false
			}
			if v2.IsNil() {
				return true
			}
			return !(column.GetRef(v1).Int() < column.GetRef(v2).Int()) != order
		}
	case reflect.Uint,
		reflect.Uint8,
		reflect.Uint16,
		reflect.Uint32,
		reflect.Uint64:
		cs.less = func(i, j int) bool {
			v1 := reflect.ValueOf(array[i])
			v2 := reflect.ValueOf(array[j])
			if v1.IsNil() {
				return false
			}
			if v2.IsNil() {
				return true
			}
			return !(column.GetRef(v1).Uint() < column.GetRef(v2).Uint()) != order
		}
	case reflect.Float32,
		reflect.Float64:
		cs.less = func(i, j int) bool {
			v1 := reflect.ValueOf(array[i])
			v2 := reflect.ValueOf(array[j])
			if v1.IsNil() {
				return false
			}
			if v2.IsNil() {
				return true
			}
			return !(column.GetRef(v1).Float() < column.GetRef(v2).Float()) != order
		}
	case reflect.String:
		cs.less = func(i, j int) bool {
			v1 := reflect.ValueOf(array[i])
			v2 := reflect.ValueOf(array[j])
			if v1.IsNil() {
				return false
			}
			if v2.IsNil() {
				return true
			}
			return !(column.GetRef(v1).String() < column.GetRef(v2).String()) != order
		}
	default:
		return nil
	}
	return cs
}

func (cs *columnSorter[T]) Len() int {
	return len(cs.array)
}

func (cs *columnSorter[T]) Swap(i, j int) {
	cs.swapper(i, j)
}

func (cs *columnSorter[T]) Less(i, j int) bool {
	return cs.less(i, j)
}
