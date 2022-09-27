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

	// set for caching (to avoid recalculation)
	tf.currentMaxWidth = maxWidth

	if len(tf.showColumns) == 0 {
		return
	}

	// Keep count of occurrences (needed when redistributing leftover space)
	occurrences := make(map[string]int)

	// width of all dividers between the columns
	dividerWidth := (len(tf.showColumns) - 1) * len([]rune(tf.options.ColumnDivider))

	// calculate the minimum required length (that is: length of dividers plus width (in case it's fixed or MinWidth is
	// set) or one character (if no width was specified)) - else we could get negative values on auto-scaling
	requiredWidth := dividerWidth

	// totalWidthNotFixed will contain all columns that haven't been set to "fixed"
	totalWidthNotFixed := 0

	// totalWidthFixed will contain dividers and all columns that have either been set to "fixed" (or in a later pass
	// have minWidth or maxWidth constraints)
	totalWidthFixed := dividerWidth

	for _, column := range tf.showColumns {
		// Reset temporary values
		column.treatAsFixed = false

		occurrences[column.col.Name]++

		if column.col.FixedWidth && !force {
			requiredWidth += column.col.Width
			totalWidthFixed += column.col.Width
			continue
		}

		totalWidthNotFixed += column.col.Width

		if column.col.MinWidth > 0 && !force {
			requiredWidth += column.col.MinWidth
			continue
		}

		// at least account one character per column
		requiredWidth++
	}

	// if force is set, we only account one character per column plus dividers
	if force {
		requiredWidth = dividerWidth + len(tf.showColumns)
	}

	// enforce at least having requiredWidth (we need to ignore maxWidth in this case)
	if requiredWidth > maxWidth {
		maxWidth = requiredWidth
	}

	// totalAdjustedWidthNotFixed stores the combined widths of all fields that have been scaled
	var totalAdjustedWidthNotFixed int

	// we might need to do several passes to satisfy the constraints
	for {
		satisfied := true

		// collect deltas when moving columns from nonFixed to fixed because of exceeding their constraints
		addToFixed := 0
		removeFromNotFixed := 0

		totalAdjustedWidthNotFixed = 0
		for _, column := range tf.showColumns {
			if (column.col.FixedWidth || column.treatAsFixed) && !force {
				if column.col.FixedWidth {
					column.calculatedWidth = column.col.Width
				}
				continue
			}

			// set calculatedWidth based on the "weight" (relative width to other columns) of this column
			column.calculatedWidth = int(math.Floor(float64(column.col.Width) / float64(totalWidthNotFixed) * float64(maxWidth-totalWidthFixed)))

			// honor min/max widths; they'll now be treated as fixed width, afterwards we'll need another pass
			if !force {
				if column.col.MaxWidth > 0 && column.calculatedWidth > column.col.MaxWidth {
					column.calculatedWidth = column.col.MaxWidth
					column.treatAsFixed = true
					satisfied = false

					addToFixed += column.calculatedWidth
					removeFromNotFixed += column.col.Width
					continue
				}
				if column.col.MinWidth > 0 && column.calculatedWidth < column.col.MinWidth {
					column.calculatedWidth = column.col.MinWidth
					column.treatAsFixed = true
					satisfied = false

					addToFixed += column.calculatedWidth
					removeFromNotFixed += column.col.Width
					continue
				}
			}
			totalAdjustedWidthNotFixed += column.calculatedWidth
		}

		if satisfied {
			break
		}
		totalWidthFixed += addToFixed
		totalWidthNotFixed -= removeFromNotFixed
	}

	// Handle leftover space (gets distributed amongst non-fixed columns)
	leftover := maxWidth - (totalAdjustedWidthNotFixed + totalWidthFixed)

distributeLeftover:
	for leftover > 0 {
		// keep track whether we actually got to distribute space (e.g. can't do that if all columns are fixed)
		spent := false

		alreadySpent := make(map[string]struct{})

		// distribute one to each remaining candidate
		for _, column := range tf.showColumns {
			if (column.col.FixedWidth || column.treatAsFixed) && !force {
				continue
			}

			// we can only distribute to columns that are used more than once if we have leftover space for all
			// occurrences
			if occ := occurrences[column.col.Name]; occ > 1 {
				if _, ok := alreadySpent[column.col.Name]; ok {
					// we already distributed to this column in this pass (on another occurrence)
					continue
				}
				if occ <= leftover {
					column.calculatedWidth += 1
					leftover -= occ
					spent = true

					if leftover == 0 {
						break distributeLeftover
					}

					alreadySpent[column.col.Name] = struct{}{}
					continue
				}
				// cannot redistribute here, since it would be used more than just once
				continue
			}

			column.calculatedWidth += 1
			leftover--
			spent = true
			if leftover == 0 {
				break distributeLeftover
			}
		}
		if !spent {
			// in case there are no columns to be resized found
			break
		}
	}

	tf.buildFillString()
}

// GetTerminalWidth returns the width of the terminal (if one is in use) or 0 otherwise
func GetTerminalWidth() int {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return 0
	}
	terminalWidth, _, err := term.GetSize(0)
	if err != nil {
		return 0
	}
	return terminalWidth
}

// AdjustWidthsToScreen will try to get the width of the screen buffer and, if successful, call RecalculateWidths with
// that value
func (tf *TextColumnsFormatter[T]) AdjustWidthsToScreen() {
	if !tf.options.AutoScale {
		return
	}

	terminalWidth := GetTerminalWidth()
	if terminalWidth == 0 {
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

	tf.buildFillString()

	// Last but not least, add column dividers
	totalWidth += len([]rune(tf.options.ColumnDivider)) * (len(tf.showColumns) - 1)

	if maxWidth == 0 || totalWidth <= maxWidth {
		// Yay, it fits! (or user doesn't care)
		return
	}

	// We did our best, but let's resize to fit to maxWidth
	tf.RecalculateWidths(maxWidth, force)
}
