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
	"io/ioutil"
	"os"
	"strings"
	"testing"

	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

// MyElement doesn't need to implement GetBaseEvent because eventtypes.Event
// already does it.
type MyElement struct {
	eventtypes.Event

	Pid  uint32 `json:"pid,omitempty"`
	Comm string `json:"comm,omitempty"`
}

var elem = &MyElement{
	Event: eventtypes.Event{
		CommonData: eventtypes.CommonData{
			Node:      "myNode",
			Namespace: "myNs",
			Pod:       "myPod",
		},
		Type: eventtypes.NORMAL,
	},
	Pid:  1234,
	Comm: "cat",
}

var errorElem = &MyElement{
	Event: eventtypes.Event{
		CommonData: eventtypes.CommonData{
			Node:      "myNode",
			Namespace: "myNs",
			Pod:       "myPod",
		},
		Type:    eventtypes.ERR,
		Message: "Error message",
	},
}

var debugElem = &MyElement{
	Event: eventtypes.Event{
		CommonData: eventtypes.CommonData{
			Node:      "myNode",
			Namespace: "myNs",
			Pod:       "myPod",
		},
		Type:    eventtypes.DEBUG,
		Message: "Debug message",
	},
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
		expectedStdErr   string
	}{
		{
			description: "JSON output mode",
			outputConfig: &OutputConfig{
				OutputMode: OutputModeJSON,
			},
			element:        elem,
			expectedValues: "{\"node\":\"myNode\",\"namespace\":\"myNs\",\"pod\":\"myPod\",\"type\":\"normal\",\"pid\":1234,\"comm\":\"cat\"}",
		},
		{
			description: "none valid column using width",
			outputConfig: &OutputConfig{
				CustomColumns: []string{"invalid-col"},
				OutputMode:    OutputModeCustomColumns,
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
				OutputMode:    OutputModeCustomColumns,
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
				OutputMode:    OutputModeCustomColumns,
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
				OutputMode:    OutputModeCustomColumns,
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
				OutputMode:    OutputModeCustomColumns,
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
				OutputMode:    OutputModeCustomColumns,
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
			description: "error case with columns",
			outputConfig: &OutputConfig{
				CustomColumns: []string{"pid", "comm"},
				OutputMode:    OutputModeCustomColumns,
			},
			columnsWidth: map[string]int{
				"pid":  -7,
				"comm": -16,
			},
			useTabs:        false,
			expectedHeader: fmt.Sprintf("%-7s %-16s ", "PID", "COMM"),
			element:        errorElem,
			expectedStdErr: fmt.Sprintf("%s: node %s, pod %s/%s: %s\n",
				errorElem.Type, errorElem.Node, errorElem.Namespace,
				errorElem.Pod, errorElem.Message),
		},
		{
			description: "error case with JSON",
			outputConfig: &OutputConfig{
				OutputMode: OutputModeJSON,
			},
			useTabs: false,
			element: errorElem,
			/// Notice it is not printed in JSON format but is sent to stderr.
			expectedStdErr: fmt.Sprintf("%s: node %s, pod %s/%s: %s\n",
				errorElem.Type, errorElem.Node, errorElem.Namespace,
				errorElem.Pod, errorElem.Message),
		},
		{
			description: "debug case (no verbose)",
			outputConfig: &OutputConfig{
				OutputMode: OutputModeJSON,
				Verbose:    false,
			},
			useTabs: false,
			element: debugElem,
		},
		{
			description: "debug case (verbose)",
			outputConfig: &OutputConfig{
				OutputMode: OutputModeJSON,
				Verbose:    true,
			},
			useTabs: false,
			element: debugElem,
			expectedStdErr: fmt.Sprintf("%s: node %s, pod %s/%s: %s\n",
				debugElem.Type, debugElem.Node, debugElem.Namespace,
				debugElem.Pod, debugElem.Message),
		},
		{
			description: "normal case using width",
			outputConfig: &OutputConfig{
				CustomColumns: []string{"pid", "comm"},
				OutputMode:    OutputModeCustomColumns,
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
				OutputMode:    OutputModeCustomColumns,
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
						sb.WriteString(fmt.Sprintf("%s", e.Comm))
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

		// get reference to original stderr and restore on exit
		originalStderr := os.Stderr
		defer func() { os.Stderr = originalStderr }()

		r, w, _ := os.Pipe()
		os.Stderr = w
		values := p.Transform(entry.element, toColumns)
		if values != entry.expectedValues {
			t.Fatalf("Failed Transform test %q (index %d): result %q expected %q",
				entry.description, i, values, entry.expectedValues)
		}
		w.Close()
		out, _ := ioutil.ReadAll(r)
		os.Stderr = originalStderr

		if (entry.expectedStdErr != "" || string(out) != "") && entry.expectedStdErr != string(out) {
			t.Fatalf("Failed Transform test %q (index %d): stderr %q expected %q",
				entry.description, i, string(out), entry.expectedStdErr)
		}
	}
}

type MyElementNoBase struct {
	Pid  uint32 `json:"pid,omitempty"`
	Comm string `json:"comm,omitempty"`
}

func (e MyElementNoBase) GetBaseEvent() *eventtypes.Event {
	return nil
}

var elemNoBase = &MyElementNoBase{
	Pid:  1234,
	Comm: "cat",
}

func TestTransformWithNoBase(t *testing.T) {
	table := []struct {
		description      string
		columnsWidth     map[string]int
		availableColumns []string
		useTabs          bool
		outputConfig     *OutputConfig
		element          *MyElementNoBase
		expectedValues   string
		expectedStdErr   string
	}{
		{
			description: "JSON output mode",
			outputConfig: &OutputConfig{
				OutputMode: OutputModeJSON,
			},
			element:        elemNoBase,
			expectedValues: "{\"pid\":1234,\"comm\":\"cat\"}",
		},
		{
			description: "normal case using width",
			outputConfig: &OutputConfig{
				CustomColumns: []string{"pid", "comm"},
				OutputMode:    OutputModeCustomColumns,
			},
			columnsWidth: map[string]int{
				"pid":  -7,
				"comm": -16,
			},
			useTabs:        false,
			element:        elemNoBase,
			expectedValues: fmt.Sprintf("%-7d %-16s ", elem.Pid, elem.Comm),
		},
		{
			description: "normal case using tabs",
			outputConfig: &OutputConfig{
				CustomColumns: []string{"pid", "comm"},
				OutputMode:    OutputModeCustomColumns,
			},
			availableColumns: []string{
				"pid",
				"comm",
			},
			useTabs:        true,
			element:        elemNoBase,
			expectedValues: fmt.Sprintf("%d\t%s\t", elem.Pid, elem.Comm),
		},
	}

	for i, entry := range table {
		var p BaseParser[MyElementNoBase]
		if entry.useTabs {
			p = NewBaseTabParser[MyElementNoBase](entry.availableColumns, entry.outputConfig)
		} else {
			p = NewBaseWidthParser[MyElementNoBase](entry.columnsWidth, entry.outputConfig)
		}

		var toColumns func(e *MyElementNoBase) string
		if entry.useTabs {
			toColumns = func(e *MyElementNoBase) string {
				var sb strings.Builder

				for _, col := range p.OutputConfig.CustomColumns {
					switch col {
					case "pid":
						sb.WriteString(fmt.Sprintf("%d", e.Pid))
					case "comm":
						sb.WriteString(fmt.Sprintf("%s", e.Comm))
					default:
						continue
					}
					sb.WriteRune('\t')
				}

				return sb.String()
			}
		} else {
			toColumns = func(e *MyElementNoBase) string {
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

		// get reference to original stderr and restore on exit
		originalStderr := os.Stderr
		defer func() { os.Stderr = originalStderr }()

		r, w, _ := os.Pipe()
		os.Stderr = w
		values := p.Transform(entry.element, toColumns)
		if values != entry.expectedValues {
			t.Fatalf("Failed Transform test %q (index %d): result %q expected %q",
				entry.description, i, values, entry.expectedValues)
		}
		w.Close()
		out, _ := ioutil.ReadAll(r)
		os.Stderr = originalStderr

		if (entry.expectedStdErr != "" || string(out) != "") && entry.expectedStdErr != string(out) {
			t.Fatalf("Failed Transform test %q (index %d): stderr %q expected %q",
				entry.description, i, string(out), entry.expectedStdErr)
		}
	}
}
