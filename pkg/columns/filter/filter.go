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

package filter

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"

	"golang.org/x/exp/constraints"
)

type comparisonType int

const (
	comparisonTypeMatch comparisonType = iota
	comparisonTypeRegex
	comparisonTypeLt
	comparisonTypeLte
	comparisonTypeGt
	comparisonTypeGte
)

type FilterSpec[T any] struct {
	value          string
	refValue       any
	comparisonType comparisonType
	compareFunc    func(entry *T) bool
	negate         bool
	regex          *regexp.Regexp
	column         *columns.Column[T]
	cols           columns.ColumnMap[T]
}

func getValueFromFilterSpec[T any](fs *FilterSpec[T], column *columns.Column[T]) (value reflect.Value, err error) {
	switch fs.column.Kind() {
	case reflect.Int,
		reflect.Int8,
		reflect.Int16,
		reflect.Int32,
		reflect.Int64:
		number, err := strconv.ParseInt(fs.value, 10, 64)
		if err != nil {
			return value, fmt.Errorf("tried to compare %q to int column %q", fs.value, column.Name)
		}
		value = reflect.ValueOf(number).Convert(column.Type())
	case reflect.Uint,
		reflect.Uint8,
		reflect.Uint16,
		reflect.Uint32,
		reflect.Uint64:
		number, err := strconv.ParseUint(fs.value, 10, 64)
		if err != nil {
			return value, fmt.Errorf("tried to compare %q to uint column %q", fs.value, column.Name)
		}
		value = reflect.ValueOf(number).Convert(column.Type())
	case reflect.Float32,
		reflect.Float64:
		number, err := strconv.ParseFloat(fs.value, 64)
		if err != nil {
			return value, fmt.Errorf("tried to compare %q to float column %q", fs.value, column.Name)
		}
		value = reflect.ValueOf(number).Convert(column.Type())
	case reflect.String:
		value = reflect.ValueOf(fs.value)
	default:
		return reflect.Value{}, fmt.Errorf("tried to match %q on unsupported column %q", fs.value, column.Name)
	}
	return value, nil
}

// GetFilterFromString prepares a filter that has a Match() function that can be called on
// entries of type *T
func GetFilterFromString[T any](cols columns.ColumnMap[T], filter string) (*FilterSpec[T], error) {
	filterInfo := strings.SplitN(filter, ":", 2)
	if len(filterInfo) == 1 {
		// special case: only a column means we match with an empty string
		filterInfo = append(filterInfo, "")
	}

	// Get column to group
	column, ok := cols.GetColumn(filterInfo[0])
	if !ok {
		return nil, fmt.Errorf("could not apply filter: column %q not found", filterInfo[0])
	}

	fs := &FilterSpec[T]{
		cols:   cols,
		column: column,
	}

	filterRule := filterInfo[1]

	fs.value = filterRule

	if strings.HasPrefix(filterRule, "!") {
		fs.negate = true
		filterRule = filterRule[1:]
		fs.value = filterRule
	}

	if strings.HasPrefix(filterRule, "~") {
		fs.comparisonType = comparisonTypeRegex
		filterRule = strings.TrimPrefix(filterRule, "~")
		fs.value = filterRule
		re, err := regexp.Compile(fs.value)
		if err != nil {
			return nil, fmt.Errorf("could not compile regular expression %q: %w", fs.value, err)
		}
		fs.regex = re
	} else if strings.HasPrefix(filterRule, ">=") {
		fs.comparisonType = comparisonTypeGte
		filterRule = strings.TrimPrefix(filterRule, ">=")
		fs.value = filterRule
	} else if strings.HasPrefix(filterRule, ">") {
		fs.comparisonType = comparisonTypeGt
		filterRule = strings.TrimPrefix(filterRule, ">")
		fs.value = filterRule
	} else if strings.HasPrefix(filterRule, "<=") {
		fs.comparisonType = comparisonTypeLte
		filterRule = strings.TrimPrefix(filterRule, "<=")
		fs.value = filterRule
	} else if strings.HasPrefix(filterRule, "<") {
		fs.comparisonType = comparisonTypeLt
		filterRule = strings.TrimPrefix(filterRule, "<")
		fs.value = filterRule
	}

	if fs.comparisonType == comparisonTypeRegex && column.Kind() != reflect.String {
		return nil, fmt.Errorf("tried to apply regular expression on non-string column %q", fs.column.Name)
	}

	// We precalculate value to be of a comparable type to column.kind when comparisonType is not comparisonTypeRegex
	var value reflect.Value
	var err error
	switch fs.comparisonType {
	case comparisonTypeMatch,
		comparisonTypeGt,
		comparisonTypeGte,
		comparisonTypeLt,
		comparisonTypeLte:
		value, err = getValueFromFilterSpec(fs, column)
		if err != nil {
			return nil, err
		}
	}

	if value.IsValid() {
		fs.refValue = value.Interface()
	}

	fs.compareFunc = fs.getComparisonFunc()

	return fs, nil
}

func (fs *FilterSpec[T]) getComparisonFunc() func(*T) bool {
	offset := fs.column.GetOffset()

	switch fs.column.Kind() {
	case reflect.Int:
		return getComparisonFuncForComparisonType[int, T](fs.comparisonType, fs.negate, offset, fs.refValue)
	case reflect.Int8:
		return getComparisonFuncForComparisonType[int8, T](fs.comparisonType, fs.negate, offset, fs.refValue)
	case reflect.Int16:
		return getComparisonFuncForComparisonType[int16, T](fs.comparisonType, fs.negate, offset, fs.refValue)
	case reflect.Int32:
		return getComparisonFuncForComparisonType[int32, T](fs.comparisonType, fs.negate, offset, fs.refValue)
	case reflect.Int64:
		return getComparisonFuncForComparisonType[int64, T](fs.comparisonType, fs.negate, offset, fs.refValue)
	case reflect.Uint:
		return getComparisonFuncForComparisonType[uint, T](fs.comparisonType, fs.negate, offset, fs.refValue)
	case reflect.Uint8:
		return getComparisonFuncForComparisonType[uint8, T](fs.comparisonType, fs.negate, offset, fs.refValue)
	case reflect.Uint16:
		return getComparisonFuncForComparisonType[uint16, T](fs.comparisonType, fs.negate, offset, fs.refValue)
	case reflect.Uint32:
		return getComparisonFuncForComparisonType[uint32, T](fs.comparisonType, fs.negate, offset, fs.refValue)
	case reflect.Uint64:
		return getComparisonFuncForComparisonType[uint64, T](fs.comparisonType, fs.negate, offset, fs.refValue)
	case reflect.String:
		if fs.comparisonType == comparisonTypeRegex {
			return func(entry *T) bool {
				return fs.regex.MatchString(columns.GetField[string](entry, fs.column.GetOffset())) != fs.negate
			}
		}
		return getComparisonFuncForComparisonType[string, T](fs.comparisonType, fs.negate, offset, fs.refValue)
	case reflect.Float32:
		return getComparisonFuncForComparisonType[float32, T](fs.comparisonType, fs.negate, offset, fs.refValue)
	case reflect.Float64:
		return getComparisonFuncForComparisonType[float64, T](fs.comparisonType, fs.negate, offset, fs.refValue)
	case reflect.Bool:
		if fs.comparisonType == comparisonTypeMatch {
			return func(entry *T) bool {
				return columns.GetField[bool](entry, offset) == fs.refValue.(bool)
			}
		}
		fallthrough
	default:
		return func(a *T) bool {
			return false
		}
	}
}

func getComparisonFuncForComparisonType[OT constraints.Ordered, T any](ct comparisonType, negate bool, offset uintptr, refValue any) func(a *T) bool {
	switch ct {
	case comparisonTypeMatch:
		return func(a *T) bool {
			return columns.GetField[OT](a, offset) == refValue.(OT) != negate
		}
	case comparisonTypeGt:
		return func(a *T) bool {
			return columns.GetField[OT](a, offset) > refValue.(OT) != negate
		}
	case comparisonTypeGte:
		return func(a *T) bool {
			return columns.GetField[OT](a, offset) >= refValue.(OT) != negate
		}
	case comparisonTypeLt:
		return func(a *T) bool {
			return columns.GetField[OT](a, offset) < refValue.(OT) != negate
		}
	case comparisonTypeLte:
		return func(a *T) bool {
			return columns.GetField[OT](a, offset) <= refValue.(OT) != negate
		}
	default:
		return func(a *T) bool {
			return false
		}
	}
}

// Match matches a single entry against the FilterSpec and returns true if it matches
func (fs *FilterSpec[T]) Match(entry *T) bool {
	if entry == nil {
		return fs.negate
	}
	return fs.compareFunc(entry)
}

// FilterEntries will return the elements of entries that match all given filters.
func FilterEntries[T any](cols columns.ColumnMap[T], entries []*T, filters []string) ([]*T, error) {
	if entries == nil {
		return nil, nil
	}

	var outEntries []*T

	for _, filter := range filters {
		fs, err := GetFilterFromString(cols, filter)
		if err != nil {
			return nil, fmt.Errorf("could not apply filter %q: %w", filter, err)
		}

		outEntries = make([]*T, 0)

		// Iterate over entries and push them to their corresponding map key
		for _, entry := range entries {
			if entry == nil {
				// Skip nil entries
				continue
			}

			if fs.Match(entry) {
				outEntries = append(outEntries, entry)
			}
		}

		entries = outEntries
	}

	return outEntries, nil
}
