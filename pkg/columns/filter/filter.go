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

	"github.com/kinvolk/inspektor-gadget/pkg/columns"

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

type filterSpec[T any] struct {
	value          string
	refValue       interface{}
	comparisonType comparisonType
	negate         bool
	regex          *regexp.Regexp
	column         *columns.Column[T]
	cols           columns.ColumnMap[T]
}

// GetFilterFromString prepares a filter that has a Match() function that can be called on
// entries of type *T
func GetFilterFromString[T any](cols columns.ColumnMap[T], filter string) (*filterSpec[T], error) {
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

	fs := &filterSpec[T]{
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

	// We precalculate value to be of a comparable type to column.kind when comparisonType is comparisonTypeMatch
	var value reflect.Value
	switch fs.comparisonType {
	case comparisonTypeMatch,
		comparisonTypeGt,
		comparisonTypeGte,
		comparisonTypeLt,
		comparisonTypeLte:
		switch fs.column.Kind() {
		case reflect.Int,
			reflect.Int8,
			reflect.Int16,
			reflect.Int32,
			reflect.Int64:
			number, err := strconv.ParseInt(fs.value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("tried to compare %q to int column %q", fs.value, column.Name)
			}
			value = reflect.ValueOf(number).Convert(column.Type())
		case reflect.Uint,
			reflect.Uint8,
			reflect.Uint16,
			reflect.Uint32,
			reflect.Uint64:
			number, err := strconv.ParseUint(fs.value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("tried to compare %q to uint column %q", fs.value, column.Name)
			}
			value = reflect.ValueOf(number).Convert(column.Type())
		case reflect.Float32,
			reflect.Float64:
			number, err := strconv.ParseFloat(fs.value, 64)
			if err != nil {
				return nil, fmt.Errorf("tried to compare %q to float column %q", fs.value, column.Name)
			}
			value = reflect.ValueOf(number).Convert(column.Type())
		case reflect.String:
			value = reflect.ValueOf(fs.value)
		default:
			return nil, fmt.Errorf("tried to match %q on unsupported column %q", fs.value, column.Name)
		}
	}

	if value.IsValid() {
		fs.refValue = value.Interface()
	}

	return fs, nil
}

func compare[T constraints.Ordered](a, b T, ct comparisonType, negate bool) bool {
	switch ct {
	case comparisonTypeMatch:
		return a == b != negate
	case comparisonTypeGt:
		return a > b != negate
	case comparisonTypeGte:
		return a >= b != negate
	case comparisonTypeLt:
		return a < b != negate
	case comparisonTypeLte:
		return a <= b != negate
	default:
		return false
	}
}

func (fs *filterSpec[T]) Match(entry *T) bool {
	if entry == nil {
		return fs.negate
	}

	field := fs.column.GetRef(reflect.ValueOf(entry))

	matches := false
	switch fs.comparisonType {
	case
		comparisonTypeMatch,
		comparisonTypeGt,
		comparisonTypeGte,
		comparisonTypeLt,
		comparisonTypeLte:
		switch fs.column.Kind() {
		case reflect.Int:
			return compare(field.Interface().(int), fs.refValue.(int), fs.comparisonType, fs.negate)
		case reflect.Int8:
			return compare(field.Interface().(int8), fs.refValue.(int8), fs.comparisonType, fs.negate)
		case reflect.Int16:
			return compare(field.Interface().(int16), fs.refValue.(int16), fs.comparisonType, fs.negate)
		case reflect.Int32:
			return compare(field.Interface().(int32), fs.refValue.(int32), fs.comparisonType, fs.negate)
		case reflect.Int64:
			return compare(field.Interface().(int64), fs.refValue.(int64), fs.comparisonType, fs.negate)
		case reflect.Uint:
			return compare(field.Interface().(uint), fs.refValue.(uint), fs.comparisonType, fs.negate)
		case reflect.Uint8:
			return compare(field.Interface().(uint8), fs.refValue.(uint8), fs.comparisonType, fs.negate)
		case reflect.Uint16:
			return compare(field.Interface().(uint16), fs.refValue.(uint16), fs.comparisonType, fs.negate)
		case reflect.Uint32:
			return compare(field.Interface().(uint32), fs.refValue.(uint32), fs.comparisonType, fs.negate)
		case reflect.Uint64:
			return compare(field.Interface().(uint64), fs.refValue.(uint64), fs.comparisonType, fs.negate)
		case reflect.Float32:
			return compare(field.Interface().(float32), fs.refValue.(float32), fs.comparisonType, fs.negate)
		case reflect.Float64:
			return compare(field.Interface().(float64), fs.refValue.(float64), fs.comparisonType, fs.negate)
		case reflect.String:
			return compare(field.Interface().(string), fs.refValue.(string), fs.comparisonType, fs.negate)
		}
	case comparisonTypeRegex:
		if fs.regex.MatchString(field.String()) {
			matches = true
		}
	}

	return matches != fs.negate
}

// FilterEntries will filter entries according to the given filters.
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
