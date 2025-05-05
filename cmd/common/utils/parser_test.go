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

package utils

import (
	"fmt"
	"strings"
	"testing"
)

type MyElement struct {
	Pid  uint32 `json:"pid,omitempty"`
	Comm string `json:"comm,omitempty"`
}

var elem = &MyElement{
	Pid:  1234,
	Comm: "cat",
}

// TODO: Test default columns (OutputModeColumns)
func TestBaseParser(t *testing.T) {
	table := []struct {
		description      string
		columnsWidth     map[string]int
		availableColumns []string
		useTabs          bool
		outputConfig     *OutputConfig
		element          *MyElement
		expectedHeader   string
		expectedValues   string
	}{
		{
			description: "JSON output mode",
			outputConfig: &OutputConfig{
				OutputMode: OutputModeJSON,
			},
			element:        elem,
			expectedValues: "{\"pid\":1234,\"comm\":\"cat\"}",
		},
		{
			description: "none valid column using width",
			outputConfig: &OutputConfig{
				CustomColumns: []string{"invalid-col"},
				OutputMode:    OutputModeColumns,
			},
			columnsWidth: map[string]int{
				"pid":  0,
				"comm": 0,
			},
			element: elem,
		},
		{
			description: "none valid column using tabs",
			outputConfig: &OutputConfig{
				CustomColumns: []string{"invalid-col"},
				OutputMode:    OutputModeColumns,
			},
			availableColumns: []string{
				"pid",
				"comm",
			},
			useTabs: true,
			element: elem,
		},
		{
			description: "ignore invalid column using width",
			outputConfig: &OutputConfig{
				CustomColumns: []string{"pid", "invalid-col"},
				OutputMode:    OutputModeColumns,
			},
			columnsWidth: map[string]int{
				"pid":  -7,
				"comm": -16,
			},
			useTabs:        false,
			expectedHeader: fmt.Sprintf("%-7s ", "PID"),
			element:        elem,
			expectedValues: fmt.Sprintf("%-7d ", elem.Pid),
		},
		{
			description: "ignore invalid column using tabs",
			outputConfig: &OutputConfig{
				CustomColumns: []string{"pid", "invalid-col"},
				OutputMode:    OutputModeColumns,
			},
			availableColumns: []string{
				"pid",
				"comm",
			},
			useTabs:        true,
			expectedHeader: fmt.Sprintf("%s\t", "PID"),
			element:        elem,
			expectedValues: fmt.Sprintf("%d\t", elem.Pid),
		},
		{
			description: "ignore multiple invalid columns using width",
			outputConfig: &OutputConfig{
				CustomColumns: []string{"pid", "invalid-col", "comm", "another-invalid-col"},
				OutputMode:    OutputModeColumns,
			},
			columnsWidth: map[string]int{
				"pid":  -7,
				"comm": -16,
			},
			useTabs:        false,
			expectedHeader: fmt.Sprintf("%-7s %-16s ", "PID", "COMM"),
			element:        elem,
			expectedValues: fmt.Sprintf("%-7d %-16s ", elem.Pid, elem.Comm),
		},
		{
			description: "ignore multiple invalid column using tabs",
			outputConfig: &OutputConfig{
				CustomColumns: []string{"pid", "invalid-col", "comm", "another-invalid-col"},
				OutputMode:    OutputModeColumns,
			},
			availableColumns: []string{
				"pid",
				"comm",
			},
			useTabs:        true,
			expectedHeader: fmt.Sprintf("%s\t%s\t", "PID", "COMM"),
			element:        elem,
			expectedValues: fmt.Sprintf("%d\t%s\t", elem.Pid, elem.Comm),
		},
		{
			description: "normal case using width",
			outputConfig: &OutputConfig{
				CustomColumns: []string{"pid", "comm"},
				OutputMode:    OutputModeColumns,
			},
			columnsWidth: map[string]int{
				"pid":  -7,
				"comm": -16,
			},
			useTabs:        false,
			expectedHeader: fmt.Sprintf("%-7s %-16s ", "PID", "COMM"),
			element:        elem,
			expectedValues: fmt.Sprintf("%-7d %-16s ", elem.Pid, elem.Comm),
		},
		{
			description: "normal case using tabs",
			outputConfig: &OutputConfig{
				CustomColumns: []string{"pid", "comm"},
				OutputMode:    OutputModeColumns,
			},
			availableColumns: []string{
				"pid",
				"comm",
			},
			useTabs:        true,
			expectedHeader: fmt.Sprintf("%s\t%s\t", "PID", "COMM"),
			element:        elem,
			expectedValues: fmt.Sprintf("%d\t%s\t", elem.Pid, elem.Comm),
		},
	}

	for i, entry := range table {
		var p BaseParser[MyElement]
		if entry.useTabs {
			p = NewBaseTabParser[MyElement](entry.availableColumns, entry.outputConfig)
		} else {
			p = NewBaseWidthParser[MyElement](entry.columnsWidth, entry.outputConfig)
		}

		header := p.BuildColumnsHeader()
		if header != entry.expectedHeader {
			t.Fatalf("Failed BuildColumnsHeader test %q (index %d): result %q expected %q",
				entry.description, i, header, entry.expectedHeader)
		}

		var toColumns func(e *MyElement) string
		if entry.useTabs {
			toColumns = func(e *MyElement) string {
				var sb strings.Builder

				for _, col := range p.OutputConfig.CustomColumns {
					switch col {
					case "pid":
						sb.WriteString(fmt.Sprintf("%d", e.Pid))
					case "comm":
						sb.WriteString(e.Comm)
					default:
						continue
					}
					sb.WriteRune('\t')
				}

				return sb.String()
			}
		} else {
			toColumns = func(e *MyElement) string {
				var sb strings.Builder

				for _, col := range p.OutputConfig.CustomColumns {
					switch col {
					case "pid":
						sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], e.Pid))
					case "comm":
						sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], e.Comm))
					default:
						continue
					}
					sb.WriteRune(' ')
				}

				return sb.String()
			}
		}

		values := p.Transform(entry.element, toColumns)
		if values != entry.expectedValues {
			t.Fatalf("Failed Transform test %q (index %d): result %q expected %q",
				entry.description, i, values, entry.expectedValues)
		}
	}
}
