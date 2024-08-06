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

package textcolumns

import (
	"bytes"
	"io"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/ellipsis"
)

func (tf *TextColumnsFormatter[T]) setFormatter(column *Column[T]) {
	ff := columns.GetFieldAsStringExt[T](column.col, 'f', column.col.Precision, column.col.Hex)
	column.formatter = func(entry *T) string {
		return tf.buildFixedString(ff(entry), column.calculatedWidth, column.col.EllipsisType, column.col.Alignment)
	}
}

func (tf *TextColumnsFormatter[T]) buildFixedString(s string, length int, ellipsisType ellipsis.EllipsisType, alignment columns.Alignment) string {
	if length <= 0 {
		return ""
	}

	if !tf.options.ShouldTruncate {
		return s
	}

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

	var row strings.Builder
	for i, col := range tf.showColumns {
		if i > 0 {
			row.WriteString(tf.options.ColumnDivider)
		}
		row.WriteString(col.formatter(entry))
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

// FormatTable returns header, divider and the formatted entries with the current settings as a string
func (tf *TextColumnsFormatter[T]) FormatTable(entries []*T) string {
	buf := bytes.NewBuffer(nil)
	_ = tf.WriteTable(buf, entries)
	out := buf.Bytes()
	return string(out[:len(out)-1])
}

// WriteTable writes header, divider and the formatted entries with the current settings to writer
func (tf *TextColumnsFormatter[T]) WriteTable(writer io.Writer, entries []*T) error {
	_, err := writer.Write([]byte(tf.FormatHeader()))
	if err != nil {
		return err
	}
	_, err = writer.Write([]byte("\n"))
	if err != nil {
		return err
	}
	if tf.options.RowDivider != DividerNone {
		_, err = writer.Write([]byte(tf.FormatRowDivider()))
		if err != nil {
			return err
		}
		_, err = writer.Write([]byte("\n"))
		if err != nil {
			return err
		}
	}
	for _, entry := range entries {
		_, err = writer.Write([]byte(tf.FormatEntry(entry)))
		if err != nil {
			return err
		}
		_, err = writer.Write([]byte("\n"))
		if err != nil {
			return err
		}
	}
	return nil
}
