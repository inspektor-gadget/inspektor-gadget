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
	"math"
	"os"
	"reflect"
	"strconv"

	"golang.org/x/term"
)

// RecalculateWidths sets the screen width and automatically scales columns to fit (if enabled in options)
// If force is true, fixed widths will also be adjusted.
func (tf *TextColumnsFormatter[T]) RecalculateWidths(maxWidth int, force bool) {
	if tf.currentMaxWidth == maxWidth {
		// No need to recalculate
		return
	}

	if len(tf.showColumns) == 0 {
		return
	}

	// calculate the minimum required length - else we could get negative values on auto-scaling
	requiredWidth := (len(tf.showColumns) - 1) * len([]rune(tf.options.ColumnDivider))
	if force {
		requiredWidth += len(tf.showColumns)
	} else {
		for _, column := range tf.showColumns {
			if column.col.FixedWidth {
				requiredWidth += column.col.Width
				continue
			}
			requiredWidth++
		}
	}

	// enforce the requiredWidth
	if requiredWidth > maxWidth {
		maxWidth = requiredWidth
	}

	tf.currentMaxWidth = maxWidth

	// Get total width of all printed columns
	totalWidth := 0
	spaces := 0
	for i, column := range tf.showColumns {
		if i > 0 {
			spaces += len([]rune(tf.options.ColumnDivider))
		}
		if column.col.FixedWidth && !force {
			spaces += column.col.Width
			continue
		}
		totalWidth += column.col.Width
	}

	// Keep count of occurrences (needed when redistributing leftover space)
	occurrences := make(map[string]int)

	// Adjust width
	totalAdjustedWidth := 0
	for _, column := range tf.showColumns {
		if column.col.FixedWidth && !force {
			column.calculatedWidth = column.col.Width
			continue
		}
		occurrences[column.col.Name]++
		column.calculatedWidth = int(math.Floor(float64(column.col.Width) / float64(totalWidth) * float64(maxWidth-spaces)))
		totalAdjustedWidth += column.calculatedWidth
	}

	// Handle leftover space
	leftover := maxWidth - (totalAdjustedWidth + spaces)
	for {
		if leftover == 0 {
			break
		}

		spent := false

		// distribute
		for _, column := range tf.showColumns {
			if column.col.FixedWidth && !force {
				continue
			}
			if occurrences[column.col.Name] > 1 {
				// cannot redistribute here, since it would be used more than just once
				continue
			}
			column.calculatedWidth += 1
			spent = true
			leftover--
			if leftover == 0 {
				break
			}
		}
		if !spent {
			// in case there are no columns to be resized found
			break
		}
	}

	tf.buildFillString()
}

// AdjustWidthsToScreen will try to get the width of the screen buffer and call RecalculateWidths with that value
func (tf *TextColumnsFormatter[T]) AdjustWidthsToScreen() {
	if !tf.options.AutoScale {
		return
	}

	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return
	}
	terminalWidth, _, err := term.GetSize(0)
	if err != nil {
		return
	}

	tf.RecalculateWidths(terminalWidth, false)
}

// AdjustWidthsToContent will calculate widths of columns by getting the maximum length found for each column
// in the input array. If considerHeaders is true, header lengths will also be considered when calculating.
// If maxWidth > 0, space will be reduced to accordingly to match the given width.
// If force is true, fixed widths will be ignored and scaled as well in the case that maxWidths is exceeded.
func (tf *TextColumnsFormatter[T]) AdjustWidthsToContent(entries []*T, considerHeaders bool, maxWidth int, force bool) {
	columnWidths := make([]int, len(tf.showColumns))
	for columnIndex, column := range tf.showColumns {
		// Get info on fixed columns first
		if column.col.FixedWidth {
			columnWidths[columnIndex] = column.calculatedWidth
		}
	}
	for _, entry := range entries {
		if entry == nil {
			continue
		}
		entryValue := reflect.ValueOf(entry)
		for columnIndex, column := range tf.showColumns {
			if column.col.FixedWidth {
				continue
			}

			field := column.col.GetRef(entryValue)

			flen := 0
			switch column.col.Kind() {
			case reflect.Int,
				reflect.Int8,
				reflect.Int16,
				reflect.Int32,
				reflect.Int64:
				flen = len([]rune((strconv.FormatInt(field.Int(), 10))))
			case reflect.Uint,
				reflect.Uint8,
				reflect.Uint16,
				reflect.Uint32,
				reflect.Uint64:
				flen = len([]rune((strconv.FormatUint(field.Uint(), 10))))
			case reflect.Float32,
				reflect.Float64:
				flen = len([]rune(strconv.FormatFloat(field.Float(), 'f', column.col.Precision, 64)))
			case reflect.String:
				flen = len([]rune(field.Interface().(string)))
			default:
				flen = len([]rune(fmt.Sprintf("%v", field.Interface())))
			}

			if columnWidths[columnIndex] < flen {
				columnWidths[columnIndex] = flen
			}
		}
	}

	if considerHeaders {
		for columnIndex, column := range tf.showColumns {
			if column.col.FixedWidth {
				continue
			}
			headerLen := len([]rune(column.col.Name))
			if headerLen > columnWidths[columnIndex] {
				columnWidths[columnIndex] = headerLen
			}
		}
	}

	// Now set calculated widths accordingly
	totalWidth := 0
	for columnIndex, column := range tf.showColumns {
		column.calculatedWidth = columnWidths[columnIndex]
		totalWidth += column.calculatedWidth
	}

	// Last but not least, add column dividers
	totalWidth += len([]rune(tf.options.ColumnDivider)) * (len(tf.showColumns) - 1)

	if maxWidth == 0 || totalWidth <= maxWidth {
		// Yay, it fits! (or user doesn't care)
		return
	}

	// We did our best, but let's resize to fit to maxWidth
	tf.RecalculateWidths(maxWidth, force)
}
