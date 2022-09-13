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

package textcolumns

import (
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"

	"github.com/kinvolk/inspektor-gadget/pkg/columns"

	"github.com/kinvolk/inspektor-gadget/pkg/columns/ellipsis"
)

func (tf *TextColumnsFormatter[T]) setFormatter(column *Column[T]) {
	switch column.col.Kind() {
	case reflect.Int,
		reflect.Int8,
		reflect.Int16,
		reflect.Int32,
		reflect.Int64:
		column.formatter = func(v interface{}) string {
			return tf.buildFixedString(strconv.FormatInt(reflect.ValueOf(v).Int(), 10), column.calculatedWidth, column.col.EllipsisType, column.col.Alignment)
		}
	case reflect.Uint,
		reflect.Uint8,
		reflect.Uint16,
		reflect.Uint32,
		reflect.Uint64:
		column.formatter = func(v interface{}) string {
			return tf.buildFixedString(strconv.FormatUint(reflect.ValueOf(v).Uint(), 10), column.calculatedWidth, column.col.EllipsisType, column.col.Alignment)
		}
	case reflect.Float32,
		reflect.Float64:
		column.formatter = func(v interface{}) string {
			return tf.buildFixedString(strconv.FormatFloat(reflect.ValueOf(v).Float(), 'f', column.col.Precision, 64), column.calculatedWidth, column.col.EllipsisType, column.col.Alignment)
		}
	case reflect.String:
		column.formatter = func(v interface{}) string {
			return tf.buildFixedString(v.(string), column.calculatedWidth, column.col.EllipsisType, column.col.Alignment)
		}
	default:
		column.formatter = func(v interface{}) string {
			return tf.buildFixedString(fmt.Sprintf("%v", v), column.calculatedWidth, column.col.EllipsisType, column.col.Alignment)
		}
	}
}

func (tf *TextColumnsFormatter[T]) buildFixedString(s string, length int, ellipsisType ellipsis.EllipsisType, alignment columns.Alignment) string {
	rs := []rune(s)

	shortened := ellipsis.Shorten(rs, length, ellipsisType)
	if len(shortened) == length {
		return string(shortened)
	}
	if alignment == columns.AlignLeft {
		return string(shortened) + tf.fillString[0:length-len(shortened)]
	}
	return tf.fillString[0:length-len(shortened)] + string(shortened)
}

// FormatEntry returns an entry as a formatted string, respecting the given formatting settings
func (tf *TextColumnsFormatter[T]) FormatEntry(entry *T) string {
	if entry == nil {
		return ""
	}

	entryValue := reflect.ValueOf(entry)

	var row strings.Builder
	for i, col := range tf.showColumns {
		if i > 0 {
			row.WriteString(tf.options.ColumnDivider)
		}
		field := col.col.GetRef(entryValue)
		row.WriteString(col.formatter(field.Interface()))
	}
	return row.String()
}

// FormatHeader returns the formatted header line with all visible column names, separated by ColumnDivider
func (tf *TextColumnsFormatter[T]) FormatHeader() string {
	tf.AdjustWidthsToScreen()
	var row strings.Builder
	for i, column := range tf.showColumns {
		if i > 0 {
			row.WriteString(tf.options.ColumnDivider)
		}
		name := column.col.Name
		switch tf.options.HeaderStyle {
		case HeaderStyleUppercase:
			name = strings.ToUpper(name)
		case HeaderStyleLowercase:
			name = strings.ToLower(name)
		}
		row.WriteString(tf.buildFixedString(name, column.calculatedWidth, ellipsis.End, column.col.Alignment))
	}
	return row.String()
}

// FormatRowDivider returns a string that repeats the defined RowDivider until the total length of a row is reached
func (tf *TextColumnsFormatter[T]) FormatRowDivider() string {
	if tf.options.RowDivider == DividerNone {
		return ""
	}
	var row strings.Builder
	rowDividerLen := 0
	for i, col := range tf.showColumns {
		if i > 0 {
			rowDividerLen += len([]rune(tf.options.ColumnDivider))
		}
		rowDividerLen += col.calculatedWidth
	}
	for i := 0; i < rowDividerLen; i += len([]rune(tf.options.RowDivider)) {
		row.WriteString(tf.options.RowDivider)
	}
	return string([]rune(row.String())[:rowDividerLen])
}

// WriteTable writes header, divider and body with the current settings, where the body consists of the entries given
// to the writer
func (tf *TextColumnsFormatter[T]) WriteTable(writer io.Writer, entries []*T) {
	writer.Write([]byte(tf.FormatHeader()))
	writer.Write([]byte("\n"))
	if tf.options.RowDivider != DividerNone {
		writer.Write([]byte(tf.FormatRowDivider()))
		writer.Write([]byte("\n"))
	}
	for _, entry := range entries {
		writer.Write([]byte(tf.FormatEntry(entry)))
		writer.Write([]byte("\n"))
	}
}
