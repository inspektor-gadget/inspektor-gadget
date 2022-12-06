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

package columns

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"unsafe"
)

type ColumnMap[T any] map[string]*Column[T]

type Columns[T any] struct {
	// columns map[string]*Column[T]
	ColumnMap[T]
	options *Options
}

const virtualIndex = -1

var stringType = reflect.TypeOf("") // used for virtual columns and columns with a custom extractor

// MustCreateColumns creates a new column helper and panics if it cannot successfully be created; useful if you
// want to initialize Columns as a global variable inside a package (similar to regexp.MustCompile)
func MustCreateColumns[T any](options ...Option) *Columns[T] {
	cols, err := NewColumns[T](options...)
	if err != nil {
		panic(err)
	}
	return cols
}

// NewColumns creates a new column helper. T must be of type struct and its fields must have a column tag if they
// should be considered. Struct and pointer to struct fields will be recursively traversed by default unless a column
// tag with parameter "noembed" is present. Options can be passed to change the default behavior.
func NewColumns[T any](options ...Option) (*Columns[T], error) {
	opts := GetDefault()
	for _, o := range options {
		o(opts)
	}

	entryPrototype := new(T)

	t := reflect.TypeOf(entryPrototype)
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	// Generics sadly don't provide a way to constraint to a type like struct{}, so we need to check here
	if t.Kind() != reflect.Struct {
		return nil, fmt.Errorf("NewColumns works only on structs")
	}

	columns := &Columns[T]{
		ColumnMap: make(ColumnMap[T]),
		options:   opts,
	}

	err := columns.iterateFields(t, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("error trying to initialize columns on type %s: %w", t.String(), err)
	}

	return columns, nil
}

// GetColumn returns a specific column by its name
func (c ColumnMap[T]) GetColumn(columnName string) (*Column[T], bool) {
	column, ok := c[strings.ToLower(columnName)]
	return column, ok
}

// GetColumnMap returns a map of column names to their Column, filtered by filters
func (c ColumnMap[T]) GetColumnMap(filters ...ColumnFilter) ColumnMap[T] {
	if len(filters) == 0 {
		return c
	}
	// return a new copy
	res := make(map[string]*Column[T])

filter:
	for columnName, column := range c {
		for _, f := range filters {
			if !f(column) {
				continue filter
			}
		}
		res[columnName] = column
	}
	return res
}

// GetOrderedColumns returns an ordered list of columns according to their order values, filtered by filters
func (c ColumnMap[T]) GetOrderedColumns(filters ...ColumnFilter) []*Column[T] {
	columns := make([]*Column[T], 0, len(c))

filter:
	for _, column := range c {
		for _, f := range filters {
			if !f(column) {
				continue filter
			}
		}
		columns = append(columns, column)
	}
	sort.Slice(columns, func(i, j int) bool {
		return columns[i].Order < columns[j].Order
	})
	return columns
}

// GetColumnNames returns a list of column names, ordered by the column order values
func (c ColumnMap[T]) GetColumnNames(filters ...ColumnFilter) []string {
	columns := make([]string, 0, len(c))
	sorted := c.GetOrderedColumns(filters...)
	for _, column := range sorted {
		columns = append(columns, column.Name)
	}
	return columns
}

// VerifyColumnNames takes a list of column names and returns two lists, one containing the valid column names
// and another containing the invalid column names. Prefixes like "-" for descending sorting will be ignored.
func (c ColumnMap[T]) VerifyColumnNames(columnNames []string) (valid []string, invalid []string) {
	for _, cname := range columnNames {
		cname = strings.ToLower(cname)

		// Strip prefixes
		cname = strings.TrimPrefix(cname, "-")

		if _, ok := c[cname]; ok {
			valid = append(valid, cname)
			continue
		}
		invalid = append(invalid, cname)
	}
	return
}

func (c *Columns[T]) iterateFields(t reflect.Type, sub []subField, offset uintptr) error {
	isPtr := false
	if t.Kind() == reflect.Pointer {
		if t.Elem().Kind() != reflect.Struct {
			return errors.New("unsupported pointer type")
		}
		isPtr = true
		t = t.Elem()
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)

		tag := f.Tag.Get("column")

		// If this field is a pointer to a struct or a struct, try to embed it unless a "noembed" tag is set
		if f.Type.Kind() == reflect.Struct || (f.Type.Kind() == reflect.Pointer && f.Type.Elem().Kind() == reflect.Struct) {
			if !strings.Contains(tag, ",noembed") {
				err := c.iterateFields(f.Type, append(append([]subField{}, sub...), subField{i, isPtr}), offset+f.Offset)
				if err != nil {
					return err
				}
				continue
			}
		}

		if tag == "" && c.options.RequireColumnDefinition {
			continue
		}

		if tag == "" {
			// set the name, so it will get picked up
			tag = f.Name
		}

		column := &Column[T]{
			EllipsisType: c.options.DefaultEllipsis,
			Alignment:    c.options.DefaultAlignment,
			Visible:      true,
			Precision:    2,
			offset:       offset + f.Offset,

			Order: len(c.ColumnMap) * 10,
		}

		if sub == nil {
			column.fieldIndex = i
		} else {
			// Nested structs
			column.subFieldIndex = append(append([]subField{}, sub...), subField{i, isPtr})
		}

		// store kind for faster lookups if required
		column.kind = f.Type.Kind()
		column.columnType = f.Type

		// read information from tag
		err := column.fromTag(tag)
		if err != nil {
			return fmt.Errorf("error parsing tag for %q on field %q: %w", t.Name(), f.Name, err)
		}

		if column.useTemplate {
			tpl, ok := getTemplate(column.template)
			if !ok {
				return fmt.Errorf("error applying template %q for %q on field %q: template not found", column.template, t.Name(), f.Name)
			}
			if err := column.parseTagInfo(strings.Split(tpl, ",")); err != nil {
				return fmt.Errorf("error applying template %q for %q on field %q: %w", column.template, t.Name(), f.Name, err)
			}

			// re-apply information from field tag to overwrite template settings
			err = column.fromTag(tag)
			if err != nil {
				return fmt.Errorf("error parsing tag for %q on field %q: %w", t.Name(), f.Name, err)
			}
		}

		// fall back to struct field name if column name is empty
		if column.Name == "" {
			column.Name = f.Name
		}

		if column.Width > 0 && column.MinWidth > column.Width {
			return fmt.Errorf("minWidth should not be greater than width on field %q", t.Name())
		}
		if column.MaxWidth > 0 {
			if column.MaxWidth < column.Width {
				return fmt.Errorf("maxWidth should not be less than width on field %q", t.Name())
			}
			if column.MaxWidth < column.MinWidth {
				return fmt.Errorf("maxWidth must be greater than minWidth %q", t.Name())
			}
		}

		// check if we can default to a maxWidth for this field
		if column.MaxWidth == 0 {
			column.MaxWidth = column.getWidthFromType()
		}

		if column.Width == 0 {
			column.Width = c.options.DefaultWidth
		}
		if column.MinWidth > column.Width {
			column.Width = column.MinWidth
		}

		// add optional description
		column.Description = f.Tag.Get("columnDesc")

		// add optional tags
		if tags := f.Tag.Get("columnTags"); tags != "" {
			column.Tags = strings.Split(strings.ToLower(tags), ",")
		}

		lowerName := strings.ToLower(column.Name)
		if _, ok := c.ColumnMap[lowerName]; ok {
			return fmt.Errorf("duplicate column %q for %q", lowerName, t.Name())
		}

		c.ColumnMap[lowerName] = column
	}

	return nil
}

// AddColumn adds a virtual column to the table. This virtual column requires at least a
// name and an Extractor
func (c *Columns[T]) AddColumn(column Column[T]) error {
	if column.Name == "" {
		return errors.New("no name set for column")
	}

	columnName := strings.ToLower(column.Name)
	if _, ok := c.ColumnMap[columnName]; ok {
		return fmt.Errorf("column already exists: %q", columnName)
	}

	if column.Extractor == nil {
		return fmt.Errorf("no extractor set for column %q", column.Name)
	}

	c.ColumnMap[columnName] = &column

	if column.Width == 0 {
		column.Width = c.options.DefaultWidth
	}

	column.fieldIndex = virtualIndex

	// We expect kind to be of type reflect.String because we always use the extractor func for
	// virtual columns
	column.kind = reflect.String
	column.columnType = stringType
	return nil
}

// MustAddColumn adds a new column and panics if it cannot successfully do so
func (c *Columns[T]) MustAddColumn(column Column[T]) {
	err := c.AddColumn(column)
	if err != nil {
		panic(err)
	}
}

// SetExtractor sets the extractor function for a specific column
func (c *Columns[T]) SetExtractor(columnName string, extractor func(*T) string) error {
	if extractor == nil {
		return fmt.Errorf("extractor func must be non-nil")
	}
	column, ok := c.ColumnMap[strings.ToLower(columnName)]
	if !ok {
		return fmt.Errorf("could not set extractor for unknown field %q", columnName)
	}
	column.kind = reflect.String
	column.Extractor = extractor
	column.columnType = stringType
	return nil
}

// MustSetExtractor adds a new extractor to a column and panics if it cannot successfully do so
func (c *Columns[T]) MustSetExtractor(columnName string, extractor func(*T) string) {
	err := c.SetExtractor(columnName, extractor)
	if err != nil {
		panic(fmt.Errorf("setting extractor for %q column: %w", columnName, err))
	}
}

// GetField is a helper to retrieve a value of type OT from a struct of type T given an offset
func GetField[OT any, T any](entry *T, offset uintptr) OT {
	// Keep the pointer arithmetic on one line. See:
	// https://go101.org/article/unsafe.html#pattern-convert-to-uintptr-and-back
	return *(*OT)(unsafe.Add(unsafe.Pointer(entry), offset))
}
