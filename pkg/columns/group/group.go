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

package group

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/sort"
)

func getStringFromValue(value reflect.Value) string {
	switch value.Kind() {
	case reflect.String:
		return value.String()
	case reflect.Int,
		reflect.Int8,
		reflect.Int16,
		reflect.Int32,
		reflect.Int64:
		return strconv.FormatInt(value.Int(), 10)
	case reflect.Uint,
		reflect.Uint8,
		reflect.Uint16,
		reflect.Uint32,
		reflect.Uint64:
		return strconv.FormatUint(value.Uint(), 10)
	case reflect.Float32, reflect.Float64:
		return strconv.FormatFloat(value.Float(), 'E', -1, 64)
	}
	return value.String()
}

// GroupEntries will group the given entries using the column names given in groupBy and return a new
// array with the results; if groupBy contains an empty string, all given entries will be grouped
func GroupEntries[T any](columns columns.ColumnMap[T], entries []*T, groupBy []string) ([]*T, error) {
	if entries == nil {
		return nil, nil
	}

	newEntries := entries

	for _, groupName := range groupBy {
		groupName = strings.ToLower(groupName)

		entriesVal := reflect.ValueOf(newEntries)

		// Special case: empty group
		// This means we will reduce the output to one record
		if groupName == "" {
			groupMap := make(map[string][]reflect.Value)
			allValues := make([]reflect.Value, 0, len(entries))
			for i := 0; i < entriesVal.Len(); i++ {
				if entriesVal.Index(i).IsNil() {
					// Skip nil entries
					continue
				}
				allValues = append(allValues, entriesVal.Index(i))
			}
			groupMap[""] = allValues

			outEntries := make([]*T, 0, len(groupMap))
			flattenValues(columns, &outEntries, groupMap)

			// We may exit now, since grouping more fields makes no sense after this
			return outEntries, nil
		}

		// Get column to group
		column, ok := columns.GetColumn(groupName)
		if !ok {
			return nil, fmt.Errorf("grouping by %q: column not found", groupName)
		}

		// Create a new map with key matching the group key
		groupMap := make(map[string][]reflect.Value)

		// Iterate over entries and push them to their corresponding map key
		for i := 0; i < entriesVal.Len(); i++ {
			entry := entriesVal.Index(i)
			if entry.IsNil() {
				// Skip nil entries
				continue
			}

			// Transform group key according to request
			key := getStringFromValue(column.GetRef(entry.Elem()))

			if _, ok := groupMap[key]; !ok {
				groupMap[key] = make([]reflect.Value, 0)
			}

			groupMap[key] = append(groupMap[key], entriesVal.Index(i))
		}

		outEntries := make([]*T, 0, len(groupMap))
		flattenValues(columns, &outEntries, groupMap)

		// Sort by groupName to get a deterministic result
		sort.SortEntries(columns, outEntries, []string{groupName})

		newEntries = outEntries
	}

	return newEntries, nil
}

func flattenValues[T any](cols columns.ColumnMap[T], outEntries *[]*T, groupMap map[string][]reflect.Value) {
	entriesVal := reflect.ValueOf(outEntries).Elem()

	for _, v := range groupMap {
		// Use first entry as base
		entry := reflect.New(v[0].Elem().Type())
		entry.Elem().Set(v[0].Elem())
		for i := 1; i < len(v); i++ {
			curEntry := v[i]
			for _, column := range cols.GetColumnMap() {
				switch column.GroupType {
				case columns.GroupTypeNone:
					continue
				case columns.GroupTypeSum:
					switch column.Kind() {
					case reflect.Int,
						reflect.Int8,
						reflect.Int16,
						reflect.Int32,
						reflect.Int64:
						cur := column.GetRef(entry).Int() + column.GetRef(curEntry).Int()
						column.GetRef(entry).SetInt(cur)
					case reflect.Uint,
						reflect.Uint8,
						reflect.Uint16,
						reflect.Uint32,
						reflect.Uint64:
						cur := column.GetRef(entry).Uint() + column.GetRef(curEntry).Uint()
						column.GetRef(entry).SetUint(cur)
					case reflect.Float32,
						reflect.Float64:
						cur := column.GetRef(entry).Float() + column.GetRef(curEntry).Float()
						column.GetRef(entry).SetFloat(cur)
					}
				}
			}
		}

		entriesVal = reflect.Append(entriesVal, entry)
	}

	reflect.ValueOf(outEntries).Elem().Set(entriesVal)
}
