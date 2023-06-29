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

package group

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/sort"
)

// GroupEntries will group the given entries using the column names given in groupBy and return a new
// array with the results; if groupBy contains an empty string, all given entries will be grouped
func GroupEntries[T any](cols columns.ColumnMap[T], entries []*T, groupBy []string) ([]*T, error) {
	if entries == nil {
		return nil, nil
	}

	newEntries := entries

	for _, groupName := range groupBy {
		groupName = strings.ToLower(groupName)

		// Special case: empty group
		// This means we will reduce the output to one record
		if groupName == "" {
			groupMap := make(map[string][]*T)
			allValues := make([]*T, 0, len(entries))
			for _, entry := range entries {
				if entry == nil {
					// Skip nil entries
					continue
				}
				allValues = append(allValues, entry)
			}
			groupMap[""] = allValues

			outEntries := make([]*T, 0, len(allValues))

			flattenValues(cols, &outEntries, groupMap)

			// We may exit now, since grouping more fields makes no sense after this
			return outEntries, nil
		}

		// Get column to group
		column, ok := cols.GetColumn(groupName)
		if !ok {
			return nil, fmt.Errorf("grouping by %q: column not found", groupName)
		}

		// Create a new map with key matching the group key
		groupMap := make(map[string][]*T)

		stringFunc := columns.GetFieldAsString[T](column)

		// Iterate over entries and push them to their corresponding map key
		for _, entry := range newEntries {
			if entry == nil {
				continue
			}

			// Transform group key according to request
			key := stringFunc(entry)

			if _, ok := groupMap[key]; !ok {
				groupMap[key] = make([]*T, 0)
			}

			groupMap[key] = append(groupMap[key], entry)
		}

		outEntries := make([]*T, 0, len(groupMap))
		flattenValues(cols, &outEntries, groupMap)

		// Sort by groupName to get a deterministic result
		sort.SortEntries(cols, outEntries, []string{groupName})

		newEntries = outEntries
	}

	return newEntries, nil
}

func flattenValues[T any](cols columns.ColumnMap[T], outEntries *[]*T, groupMap map[string][]*T) {
	for _, v := range groupMap {
		if len(v) == 0 {
			continue
		}
		// Use first entry as base
		entry := new(T)
		*entry = *v[0] // Copy base
		for _, curEntry := range v[1:] {
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
						fs := columns.SetFieldAsNumberFunc[int64, T](column)
						fg := columns.GetFieldAsNumberFunc[int64, T](column)
						fs(entry, fg(curEntry)+fg(entry))
					case reflect.Uint,
						reflect.Uint8,
						reflect.Uint16,
						reflect.Uint32,
						reflect.Uint64:
						fs := columns.SetFieldAsNumberFunc[uint64, T](column)
						fg := columns.GetFieldAsNumberFunc[uint64, T](column)
						fs(entry, fg(curEntry)+fg(entry))
					case reflect.Float32,
						reflect.Float64:
						fs := columns.SetFieldAsNumberFunc[float64, T](column)
						fg := columns.GetFieldAsNumberFunc[float64, T](column)
						fs(entry, fg(curEntry)+fg(entry))
					}
				}
			}
		}
		*outEntries = append(*outEntries, entry)
	}
}
