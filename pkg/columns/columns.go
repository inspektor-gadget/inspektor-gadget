// Copyright 2022-2024 The Inspektor Gadget authors
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
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/exp/constraints"
)

type ColumnMap[T any] map[string]*Column[T]

type Columns[T any] struct {
	// columns map[string]*Column[T]
	ColumnMap[T]
	options *Options
}

const (
	virtualIndex = -1
	manualIndex  = -2
)

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

	err := columns.iterateFields(t, nil, 0, "", nil)
	if err != nil {
		return nil, fmt.Errorf("trying to initialize columns on type %s: %w", t.String(), err)
	}

	return columns, nil
}

func (c *Columns[T]) AddFields(fields []DynamicField, base func(*T) unsafe.Pointer) error {
	newCols := make(map[string]*Column[T])
	for _, f := range fields {
		column := &Column[T]{
			explicitName:  true,
			offset:        f.Offset,
			fieldIndex:    manualIndex,
			kind:          f.Type.Kind(),
			columnType:    f.Type,
			rawColumnType: f.Type,
			getStart:      base,
		}

		// Copy attributes, if present
		if f.Attributes != nil {
			column.Attributes = *f.Attributes
		} else {
			// Set defaults
			column.Attributes = Attributes{
				EllipsisType: c.options.DefaultEllipsis,
				Alignment:    c.options.DefaultAlignment,
				Visible:      true,
				Precision:    2,
				Order:        len(c.ColumnMap) * 10,
			}
		}

		// Apply tag
		err := column.fromTag(f.Tag)
		if err != nil {
			return fmt.Errorf("applying tag: %w", err)
		}

		// After applying attributes and tag, we should have a name
		if column.Name == "" {
			return fmt.Errorf("missing name")
		}

		column.applyTemplate()

		lowerName := strings.ToLower(column.Name)

		if _, ok := c.ColumnMap[lowerName]; ok {
			return fmt.Errorf("duplicate column name %q", column.Name)
		}

		if _, ok := newCols[lowerName]; ok {
			return fmt.Errorf("duplicate column name %q", column.Name)
		}

		newCols[strings.ToLower(column.Name)] = column
	}

	for colName, col := range newCols {
		c.ColumnMap[colName] = col
	}
	return nil
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

func (c *Columns[T]) iterateFields(t reflect.Type, sub []subField, offset uintptr, prefix string, tags []string) error {
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
		// tagSet := len(tag) > 0

		column := &Column[T]{
			Attributes: Attributes{
				EllipsisType: c.options.DefaultEllipsis,
				Alignment:    c.options.DefaultAlignment,
				Visible:      true,
				Precision:    2,
				Order:        len(c.ColumnMap) * 10,
			},
			offset: offset + f.Offset,
		}

		// store kind for faster lookups if required
		column.kind = f.Type.Kind()
		column.columnType = f.Type
		column.rawColumnType = f.Type

		// read information from tag
		err := column.fromTag(tag)
		if err != nil {
			return fmt.Errorf("parsing tag for %q on field %q: %w", t.Name(), f.Name, err)
		}

		// add optional tags
		if tags := f.Tag.Get("columnTags"); tags != "" {
			column.Tags = strings.Split(strings.ToLower(tags), ",")
		}
		column.Tags = append(column.Tags, tags...)

		// Apply prefixes to name
		column.Name = prefix + column.Name

		// If this field is a pointer to a struct or a struct, try to embed it unless a "noembed" tag is set
		if f.Type.Kind() == reflect.Struct || (f.Type.Kind() == reflect.Pointer && f.Type.Elem().Kind() == reflect.Struct) {
			if !strings.Contains(tag, ",noembed") {
				newOffset := offset + f.Offset
				if f.Type.Kind() == reflect.Pointer {
					newOffset = 0 // offset of the struct pointed to will begin at zero again
				}
				newPrefix := prefix

				// If not explicit name was set for this field, don't inherit a new prefix
				if column.explicitName {
					newPrefix = column.Name + "."
				}
				err := c.iterateFields(
					f.Type,
					append(append([]subField{}, sub...), subField{
						index:       i,
						offset:      offset + f.Offset,
						parentIsPtr: isPtr,
						isPtr:       f.Type.Kind() == reflect.Pointer,
					}),
					newOffset,
					newPrefix,
					append(tags, column.Tags...),
				)
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

		if sub == nil {
			column.fieldIndex = i
		} else {
			// Nested structs
			column.subFieldIndex = append(append([]subField{}, sub...), subField{i, offset + f.Offset, isPtr, false})
		}

		if column.useTemplate {
			err := column.applyTemplate()
			if err != nil {
				return err
			}
			// re-apply information from field tag to overwrite template settings
			err = column.fromTag(tag)
			if err != nil {
				return fmt.Errorf("parsing tag for %q on field %q: %w", t.Name(), f.Name, err)
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
func (c *Columns[T]) AddColumn(attributes Attributes, extractor func(*T) any) error {
	if attributes.Name == "" {
		return errors.New("no name set for column")
	}
	if extractor == nil {
		return fmt.Errorf("no extractor set for column %q", attributes.Name)
	}

	var temp T
	typ := reflect.TypeOf(extractor(&temp))

	column := Column[T]{
		Attributes:    attributes,
		Extractor:     extractor,
		fieldIndex:    virtualIndex,
		kind:          typ.Kind(),
		columnType:    typ,
		rawColumnType: typ,
	}

	column.applyTemplate()

	columnName := strings.ToLower(column.Name)
	if _, ok := c.ColumnMap[columnName]; ok {
		return fmt.Errorf("duplicate column name %q", column.Name)
	}

	if column.Width == 0 {
		column.Width = c.options.DefaultWidth
	}

	c.ColumnMap[columnName] = &column
	return nil
}

// MustAddColumn adds a new column and panics if it cannot successfully do so
func (c *Columns[T]) MustAddColumn(attributes Attributes, extractor func(*T) any) {
	err := c.AddColumn(attributes, extractor)
	if err != nil {
		panic(err)
	}
}

// SetExtractor sets the extractor function for a specific column
func (c *Columns[T]) SetExtractor(columnName string, extractor func(*T) any) error {
	if extractor == nil {
		return fmt.Errorf("extractor func must be non-nil")
	}
	column, ok := c.ColumnMap[strings.ToLower(columnName)]
	if !ok {
		return fmt.Errorf("field %q not found", columnName)
	}

	var temp T
	typ := reflect.TypeOf(extractor(&temp))

	column.kind = typ.Kind()
	column.Extractor = extractor
	column.columnType = typ
	return nil
}

// MustSetExtractor adds a new extractor to a column and panics if it cannot successfully do so
func (c *Columns[T]) MustSetExtractor(columnName string, extractor func(*T) any) {
	err := c.SetExtractor(columnName, extractor)
	if err != nil {
		panic(fmt.Errorf("setting extractor for %q column: %w", columnName, err))
	}
}

// ColumnInternals is a non-generic interface to return internal values of columns like offsets
// for faster access.
type ColumnInternals interface {
	getOffset() uintptr
	getSubFields() []subField
	IsVirtual() bool
	HasCustomExtractor() bool
}

// GetFieldFunc returns a helper function to access the value of type OT of a struct T
// without using reflection. It differentiates between direct members of the struct and
// members of embedded structs. If any of the embedded structs being accessed is a nil-pointer,
// the default value of OT will be returned. Custom extractors will be preferred.
func GetFieldFunc[OT any, T any](column ColumnInternals) func(entry *T) OT {
	return GetFieldFuncExt[OT, T](column, false)
}

// GetFieldFuncExt returns a helper function to access the value of type OT of a struct T
// without using reflection. It differentiates between direct members of the struct and
// members of embedded structs. If any of the embedded structs being accessed is a nil-pointer,
// the default value of OT will be returned. If raw is set, even if a custom extractor has been
// set, the returned func will access the underlying values.
func GetFieldFuncExt[OT any, T any](column ColumnInternals, raw bool) func(entry *T) OT {
	if column.IsVirtual() || (column.HasCustomExtractor() && !raw) {
		return func(entry *T) OT {
			return column.(*Column[T]).Extractor(entry).(OT)
		}
	}
	sub := column.getSubFields()
	offset := column.getOffset()
	subLen := len(sub)
	if subLen == 0 {
		return func(entry *T) OT {
			start := unsafe.Pointer(entry)
			if column.(*Column[T]).getStart != nil {
				start = column.(*Column[T]).getStart(entry)
				if start == nil {
					return *new(OT)
				}
			}
			// Previous note was outdated since we weren't using uintptr here
			return *(*OT)(unsafe.Add(start, offset))
		}
	}

	return func(entry *T) OT {
		start := unsafe.Pointer(entry)
		if column.(*Column[T]).getStart != nil {
			start = column.(*Column[T]).getStart(entry)
			if start == nil {
				return *new(OT)
			}
		}
		for i := 0; i < subLen-1; i++ {
			if sub[i].isPtr {
				start = unsafe.Add(start, sub[i].offset) // now pointing at the pointer
				start = unsafe.Pointer(*(*uintptr)(start))
				if start == nil {
					// If we at any time hit a nil-pointer, we return the default
					// value of type OT
					var defaultValue OT
					return defaultValue
				}
			}
		}
		return *(*OT)(unsafe.Add(start, (sub)[subLen-1].offset))
	}
}

// GetFieldAsArrayFunc returns a helper function to access an array of type OT of a struct T
// without using reflection. It does not differentiate between direct members of the struct and
// members of embedded structs.
func GetFieldAsArrayFunc[OT any, T any](column ColumnInternals) func(entry *T) []OT {
	l := column.(*Column[T]).RawType().Len()

	return func(entry *T) []OT {
		entryStart := unsafe.Pointer(entry)
		if column.(*Column[T]).getStart != nil {
			entryStart = column.(*Column[T]).getStart(entry)
		}

		fieldStart := unsafe.Add(entryStart, column.getOffset())
		srcSlice := unsafe.Slice((*OT)(fieldStart), l)
		r := make([]OT, l)
		copy(r, srcSlice)
		return r
	}
}

// SetFieldFunc returns a helper function to set the value of type OT to a member of struct T
// without using reflection. It differentiates between direct members of the struct and
// members of embedded structs. If any of the embedded structs being accessed is a nil-pointer,
// no value will be set
func SetFieldFunc[OT any, T any](column ColumnInternals) func(entry *T, val OT) {
	// We cannot write to virtual columns
	if column.IsVirtual() {
		return func(entry *T, val OT) {
		}
	}
	sub := column.getSubFields()
	offset := column.getOffset()
	subLen := len(sub)
	if subLen == 0 {
		return func(entry *T, val OT) {
			start := unsafe.Pointer(entry)
			if column.(*Column[T]).getStart != nil {
				start = column.(*Column[T]).getStart(entry)
			}
			// Previous note was outdated since we weren't using uintptr here
			*(*OT)(unsafe.Add(start, offset)) = val
		}
	}

	return func(entry *T, val OT) {
		start := unsafe.Pointer(entry)
		if column.(*Column[T]).getStart != nil {
			start = column.(*Column[T]).getStart(entry)
		}
		for i := 0; i < subLen-1; i++ {
			if sub[i].isPtr {
				start = unsafe.Add(start, sub[i].offset) // now pointing at the pointer
				start = unsafe.Pointer(*(*uintptr)(start))
				if start == nil {
					// If we at any time hit a nil-pointer, we cannot set the value
					return
				}
			}
		}
		*(*OT)(unsafe.Add(start, (sub)[subLen-1].offset)) = val
	}
}

func GetFieldAsStringExt[T any](column ColumnInternals, floatFormat byte, floatPrecision int, hex bool) func(entry *T) string {
	switch column.(*Column[T]).Kind() {
	case reflect.Int,
		reflect.Int8,
		reflect.Int16,
		reflect.Int32,
		reflect.Int64:
		ff := GetFieldAsNumberFunc[int64, T](column)
		if hex {
			return func(entry *T) string {
				return "0x" + strings.ToUpper(strconv.FormatInt(ff(entry), 16))
			}
		}
		return func(entry *T) string {
			return strconv.FormatInt(ff(entry), 10)
		}
	case reflect.Uint,
		reflect.Uint8,
		reflect.Uint16,
		reflect.Uint32,
		reflect.Uint64:
		ff := GetFieldAsNumberFunc[uint64, T](column)
		if hex {
			return func(entry *T) string {
				return "0x" + strings.ToUpper(strconv.FormatUint(ff(entry), 16))
			}
		}
		return func(entry *T) string {
			return strconv.FormatUint(ff(entry), 10)
		}
	case reflect.Float32, reflect.Float64:
		ff := GetFieldAsNumberFunc[float64, T](column)
		return func(entry *T) string {
			return strconv.FormatFloat(ff(entry), floatFormat, floatPrecision, 64)
		}
	case reflect.Bool:
		ff := GetFieldFunc[bool, T](column)
		return func(entry *T) string {
			if ff(entry) {
				return "true"
			}
			return "false"
		}
	case reflect.Array:
		s := column.(*Column[T]).Type().Elem().Size()
		// c strings: []char null terminated
		if s == 1 {
			return func(entry *T) string {
				arr := GetFieldAsArrayFunc[byte, T](column)(entry)
				i := bytes.IndexByte(arr, 0)
				if i != -1 {
					arr = arr[:i]
				}
				return string(arr)
			}
		}

		return func(entry *T) string {
			return "TODO"
		}
	case reflect.Slice:
		s := column.(*Column[T]).Type().Elem().Size()
		if s == 1 {
			ff := GetFieldFunc[[]byte, T](column)
			return func(entry *T) string {
				return string(ff(entry))
			}
		}

		return func(entry *T) string {
			return "TODO"
		}
	case reflect.Map:
		keyType := column.(*Column[T]).Type().Key()
		valueType := column.(*Column[T]).Type().Elem()

		if keyType.Kind() == reflect.String && valueType.Kind() == reflect.String {
			ff := GetFieldFunc[map[string]string, T](column)
			return func(entry *T) string {
				m := ff(entry)
				kvPairs := make([]string, 0, len(m))
				for k, v := range m {
					kvPairs = append(kvPairs, fmt.Sprintf("%s=%s", k, v))
				}
				sort.Strings(kvPairs)
				return strings.Join(kvPairs, ",")
			}
		}

		return func(entry *T) string {
			return "TODO"
		}
	case reflect.String:
		return GetFieldFunc[string, T](column)
	}
	return func(entry *T) string {
		return ""
	}
}

func GetFieldAsString[T any](column ColumnInternals) func(entry *T) string {
	return GetFieldAsStringExt[T](column, 'E', -1, false)
}

// GetFieldAsNumberFunc returns a helper function to access a field of struct T as a number.
func GetFieldAsNumberFunc[OT constraints.Integer | constraints.Float, T any](column ColumnInternals) func(entry *T) OT {
	switch column.(*Column[T]).Kind() {
	default:
		var defaultValue OT
		return func(entry *T) OT {
			return defaultValue
		}
	case reflect.Int:
		ff := GetFieldFunc[int, T](column)
		return func(entry *T) OT {
			return OT(ff(entry))
		}
	case reflect.Int8:
		ff := GetFieldFunc[int8, T](column)
		return func(entry *T) OT {
			return OT(ff(entry))
		}
	case reflect.Int16:
		ff := GetFieldFunc[int16, T](column)
		return func(entry *T) OT {
			return OT(ff(entry))
		}
	case reflect.Int32:
		ff := GetFieldFunc[int32, T](column)
		return func(entry *T) OT {
			return OT(ff(entry))
		}
	case reflect.Int64:
		ff := GetFieldFunc[int64, T](column)
		return func(entry *T) OT {
			return OT(ff(entry))
		}
	case reflect.Uint:
		ff := GetFieldFunc[uint, T](column)
		return func(entry *T) OT {
			return OT(ff(entry))
		}
	case reflect.Uint8:
		ff := GetFieldFunc[uint8, T](column)
		return func(entry *T) OT {
			return OT(ff(entry))
		}
	case reflect.Uint16:
		ff := GetFieldFunc[uint16, T](column)
		return func(entry *T) OT {
			return OT(ff(entry))
		}
	case reflect.Uint32:
		ff := GetFieldFunc[uint32, T](column)
		return func(entry *T) OT {
			return OT(ff(entry))
		}
	case reflect.Uint64:
		ff := GetFieldFunc[uint64, T](column)
		return func(entry *T) OT {
			return OT(ff(entry))
		}
	case reflect.Float32:
		ff := GetFieldFunc[float32, T](column)
		return func(entry *T) OT {
			return OT(ff(entry))
		}
	case reflect.Float64:
		ff := GetFieldFunc[float64, T](column)
		return func(entry *T) OT {
			return OT(ff(entry))
		}
	}
}

// SetFieldAsNumberFunc returns a helper function to set a field of struct T to a number.
func SetFieldAsNumberFunc[OT constraints.Integer | constraints.Float, T any](column ColumnInternals) func(entry *T, value OT) {
	switch column.(*Column[T]).Kind() {
	case reflect.Int:
		ff := SetFieldFunc[int, T](column)
		return func(entry *T, value OT) {
			ff(entry, int(value))
		}
	case reflect.Int8:
		ff := SetFieldFunc[int8, T](column)
		return func(entry *T, value OT) {
			ff(entry, int8(value))
		}
	case reflect.Int16:
		ff := SetFieldFunc[int16, T](column)
		return func(entry *T, value OT) {
			ff(entry, int16(value))
		}
	case reflect.Int32:
		ff := SetFieldFunc[int32, T](column)
		return func(entry *T, value OT) {
			ff(entry, int32(value))
		}
	case reflect.Int64:
		ff := SetFieldFunc[int64, T](column)
		return func(entry *T, value OT) {
			ff(entry, int64(value))
		}
	case reflect.Uint:
		ff := SetFieldFunc[uint, T](column)
		return func(entry *T, value OT) {
			ff(entry, uint(value))
		}
	case reflect.Uint8:
		ff := SetFieldFunc[uint8, T](column)
		return func(entry *T, value OT) {
			ff(entry, uint8(value))
		}
	case reflect.Uint16:
		ff := SetFieldFunc[uint16, T](column)
		return func(entry *T, value OT) {
			ff(entry, uint16(value))
		}
	case reflect.Uint32:
		ff := SetFieldFunc[uint32, T](column)
		return func(entry *T, value OT) {
			ff(entry, uint32(value))
		}
	case reflect.Uint64:
		ff := SetFieldFunc[uint64, T](column)
		return func(entry *T, value OT) {
			ff(entry, uint64(value))
		}
	case reflect.Float32:
		ff := SetFieldFunc[float32, T](column)
		return func(entry *T, value OT) {
			ff(entry, float32(value))
		}
	case reflect.Float64:
		ff := SetFieldFunc[float64, T](column)
		return func(entry *T, value OT) {
			ff(entry, float64(value))
		}
	}
	return func(entry *T, value OT) {}
}
