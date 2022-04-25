// Copyright 2019-2022 The Inspektor Gadget authors
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

package top

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/biotop/types"
)

var blockIONodeStats map[string][]types.Stats

// flags
var blockIOSortBy types.SortBy

var blockIOCmd = &cobra.Command{
	Use:   fmt.Sprintf("block-io [interval=%d]", types.IntervalDefault),
	Short: "Trace block devices I/O",
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error

		blockIONodeStats = make(map[string][]types.Stats)

		if len(args) == 1 {
			outputInterval, err = strconv.Atoi(args[0])
			if err != nil {
				return utils.WrapInErrInvalidArg("<interval>", fmt.Errorf("%q is not a valid value", args[0]))
			}
		} else {
			outputInterval = types.IntervalDefault
		}

		config := &utils.TraceConfig{
			GadgetName:       "biotop",
			Operation:        "start",
			TraceOutputMode:  "Stream",
			TraceOutputState: "Started",
			CommonFlags:      &params,
			Parameters: map[string]string{
				types.IntervalParam: strconv.Itoa(outputInterval),
				types.MaxRowsParam:  strconv.Itoa(maxRows),
				types.SortByParam:   sortBy,
			},
		}

		// only wants to run for a given amount of time and print
		// that result.
		singleShot := params.Timeout == outputInterval

		// start print loop if this is not a "single shoot" operation
		if singleShot {
			blockIOPrintHeader()
		} else {
			blockIOStartPrintLoop()
		}

		if err := utils.RunTraceStreamCallback(config, blockIOCallback); err != nil {
			return utils.WrapInErrRunGadget(err)
		}

		if singleShot {
			blockIOPrintEvents()
		}

		return nil
	},
	SilenceUsage: true,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		var err error
		blockIOSortBy, err = types.ParseSortBy(sortBy)
		if err != nil {
			return utils.WrapInErrInvalidArg("--sort", err)
		}

		return nil
	},
	Args: cobra.MaximumNArgs(1),
}

func init() {
	addTopCommand(blockIOCmd, types.MaxRowsDefault, types.SortBySlice)
}

func blockIOCallback(line string, node string) {
	mutex.Lock()
	defer mutex.Unlock()

	var event types.Event

	if err := json.Unmarshal([]byte(line), &event); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s", utils.WrapInErrUnmarshalOutput(err, line))
		return
	}

	if event.Error != "" {
		fmt.Fprintf(os.Stderr, "Error: failed on node %q: %s", event.Node, event.Error)
		return
	}

	blockIONodeStats[node] = event.Stats
}

func blockIOStartPrintLoop() {
	go func() {
		ticker := time.NewTicker(time.Duration(outputInterval) * time.Second)
		for {
			_ = <-ticker.C
			blockIOPrintHeader()
			blockIOPrintEvents()
		}
	}()
}

func blockIOPrintHeader() {
	switch params.OutputMode {
	case utils.OutputModeColumns:
		if term.IsTerminal(int(os.Stdout.Fd())) {
			utils.ClearScreen()
		} else {
			fmt.Println("")
		}

		fmt.Printf("%-16s %-16s %-16s %-16s %-7s %-16s %-3s %-6s %-6s %-7s %-8s %s\n",
			"NODE", "NAMESPACE", "POD", "CONTAINER",
			"PID", "COMM", "R/W", "MAJOR", "MINOR", "BYTES", "TIME(µs)", "IOs")
	case utils.OutputModeCustomColumns:
		if term.IsTerminal(int(os.Stdout.Fd())) {
			utils.ClearScreen()
		} else {
			fmt.Println("")
		}
		fmt.Println(blockIOGetCustomColsHeader(params.CustomColumns))
	}
}

func blockIOPrintEvents() {
	// sort and print events
	mutex.Lock()

	stats := []types.Stats{}
	for _, stat := range blockIONodeStats {
		stats = append(stats, stat...)
	}
	blockIONodeStats = make(map[string][]types.Stats)

	mutex.Unlock()

	types.SortStats(stats, blockIOSortBy)

	switch params.OutputMode {
	case utils.OutputModeColumns:
		for idx, event := range stats {
			if idx == maxRows {
				break
			}

			rw := 'R'
			if event.Write {
				rw = 'W'
			}

			fmt.Printf("%-16s %-16s %-16s %-16s %-7d %-16s %-3c %-6d %-6d %-7d %-8d %d\n",
				event.Node, event.Namespace, event.Pod, event.Container,
				event.Pid, event.Comm, rw, event.Major, event.Minor, event.Bytes,
				event.MicroSecs, event.Operations)
		}
	case utils.OutputModeJSON:
		b, err := json.Marshal(stats)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s", utils.WrapInErrMarshalOutput(err))
			return
		}
		fmt.Println(string(b))
	case utils.OutputModeCustomColumns:
		for idx, stat := range stats {
			if idx == maxRows {
				break
			}
			fmt.Println(blockIOFormatEventCustomCols(&stat, params.CustomColumns))
		}
	}
}

func blockIOGetCustomColsHeader(cols []string) string {
	var sb strings.Builder

	for _, col := range cols {
		switch col {
		case "node":
			sb.WriteString(fmt.Sprintf("%-16s", "NODE"))
		case "namespace":
			sb.WriteString(fmt.Sprintf("%-16s", "NAMESPACE"))
		case "pod":
			sb.WriteString(fmt.Sprintf("%-16s", "POD"))
		case "container":
			sb.WriteString(fmt.Sprintf("%-16s", "CONTAINER"))
		case "pid":
			sb.WriteString(fmt.Sprintf("%-7s", "PID"))
		case "comm":
			sb.WriteString(fmt.Sprintf("%-16s", "COMM"))
		case "r/w":
			sb.WriteString(fmt.Sprintf("%-3s", "R/W"))
		case "major":
			sb.WriteString(fmt.Sprintf("%-6s", "MAJOR"))
		case "minor":
			sb.WriteString(fmt.Sprintf("%-6s", "MINOR"))
		case "bytes":
			sb.WriteString(fmt.Sprintf("%-7s", "BYTES"))
		case "time":
			sb.WriteString(fmt.Sprintf("%-8s", "TIME(µs)"))
		case "ios":
			sb.WriteString(fmt.Sprintf("%-8s", "IOs"))
		}
		sb.WriteRune(' ')
	}

	return sb.String()
}

func blockIOFormatEventCustomCols(stats *types.Stats, cols []string) string {
	var sb strings.Builder

	for _, col := range cols {
		switch col {
		case "node":
			sb.WriteString(fmt.Sprintf("%-16s", stats.Node))
		case "namespace":
			sb.WriteString(fmt.Sprintf("%-16s", stats.Namespace))
		case "pod":
			sb.WriteString(fmt.Sprintf("%-16s", stats.Pod))
		case "container":
			sb.WriteString(fmt.Sprintf("%-16s", stats.Container))
		case "pid":
			sb.WriteString(fmt.Sprintf("%-7d", stats.Pid))
		case "comm":
			sb.WriteString(fmt.Sprintf("%-16s", stats.Comm))
		case "r/w":
			rw := 'R'
			if stats.Write {
				rw = 'W'
			}

			sb.WriteString(fmt.Sprintf("%-3c", rw))
		case "major":
			sb.WriteString(fmt.Sprintf("%-6d", stats.Major))
		case "minor":
			sb.WriteString(fmt.Sprintf("%-6d", stats.Minor))
		case "bytes":
			sb.WriteString(fmt.Sprintf("%-7d", stats.Bytes))
		case "time":
			sb.WriteString(fmt.Sprintf("%-8d", stats.MicroSecs))
		case "ios":
			sb.WriteString(fmt.Sprintf("%-8d", stats.Operations))
		}
		sb.WriteRune(' ')
	}

	return sb.String()
}
