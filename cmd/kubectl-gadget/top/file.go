// Copyright 2019-2021 The Inspektor Gadget authors
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
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/filetop/types"
)

var fileNodeStats map[string][]types.Stats

var (
	// flags
	fileSortBy   types.SortBy
	fileAllFiles bool
)

var fileCmd = &cobra.Command{
	Use:   "file [interval]",
	Short: "Trace reads and writes by file",
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error

		fileNodeStats = make(map[string][]types.Stats)

		if len(args) == 1 {
			outputInterval, err = strconv.Atoi(args[0])
			if err != nil {
				return utils.WrapInErrInvalidArg("<interval>",
					fmt.Errorf("%q is not a valid value", args[0]))
			}
		} else {
			outputInterval = types.IntervalDefault
		}

		config := &utils.TraceConfig{
			GadgetName:       "filetop",
			Operation:        "start",
			TraceOutputMode:  "Stream",
			TraceOutputState: "Started",
			CommonFlags:      &params,
			Parameters: map[string]string{
				types.MaxRowsParam:  strconv.Itoa(maxRows),
				types.IntervalParam: strconv.Itoa(outputInterval),
				types.SortByParam:   sortBy,
				types.AllFilesParam: strconv.FormatBool(fileAllFiles),
			},
		}

		// when params.Timeout == interval it means the user
		// only wants to run for a given amount of time and print
		// that result.
		singleShot := params.Timeout == outputInterval

		// start print loop if this is not a "single shoot" operation
		if singleShot {
			filePrintHeader()
		} else {
			fileStartOutputLoop()
		}

		err = utils.RunTraceStreamCallback(config, fileCallback)
		if err != nil {
			return utils.WrapInErrRunGadget(err)
		}

		if singleShot {
			filePrintEvents()
		}

		return nil
	},
	SilenceUsage: true,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		var err error
		fileSortBy, err = types.ParseSortBy(sortBy)
		if err != nil {
			return utils.WrapInErrInvalidArg("--sort", err)
		}

		return nil
	},
	Args: cobra.MaximumNArgs(1),
}

func init() {
	fileCmd.Flags().BoolVarP(&fileAllFiles, "all-files", "a", types.AllFilesDefault, "Include non-regular file types (sockets, FIFOs, etc)")

	addTopCommand(fileCmd, types.MaxRowsDefault, types.SortBySlice)
}

func fileCallback(line string, node string) {
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

	fileNodeStats[node] = event.Stats
}

func fileStartOutputLoop() {
	go func() {
		ticker := time.NewTicker(time.Duration(outputInterval) * time.Second)
		filePrintHeader()
		for {
			_ = <-ticker.C
			filePrintHeader()
			filePrintEvents()
		}
	}()
}

func filePrintHeader() {
	switch params.OutputMode {
	case utils.OutputModeColumns:
		if term.IsTerminal(int(os.Stdout.Fd())) {
			utils.ClearScreen()
		} else {
			fmt.Println("")
		}
		fmt.Printf("%-16s %-16s %-16s %-16s %-7s %-16s %-6s %-6s %-7s %-7s %1s %s\n",
			"NODE", "NAMESPACE", "POD", "CONTAINER",
			"PID", "COMM", "READS", "WRITES", "R_Kb", "W_Kb", "T", "FILE")
	case utils.OutputModeCustomColumns:
		if term.IsTerminal(int(os.Stdout.Fd())) {
			utils.ClearScreen()
		} else {
			fmt.Println("")
		}
		fmt.Println(fileGetCustomColsHeader(params.CustomColumns))
	}
}

func filePrintEvents() {
	// sort and print events
	mutex.Lock()

	stats := []types.Stats{}
	for _, stat := range fileNodeStats {
		stats = append(stats, stat...)
	}
	fileNodeStats = make(map[string][]types.Stats)

	mutex.Unlock()

	types.SortStats(stats, fileSortBy)

	switch params.OutputMode {
	case utils.OutputModeColumns:
		for idx, event := range stats {
			if idx == maxRows {
				break
			}
			fmt.Printf("%-16s %-16s %-16s %-16s %-7d %-16s %-6d %-6d %-7d %-7d %c %s\n",
				event.Node, event.Namespace, event.Pod, event.Container,
				event.Pid, event.Comm, event.Reads, event.Writes, event.ReadBytes/1024,
				event.WriteBytes/1024, event.FileType, event.Filename)
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
			fmt.Println(fileFormatEventCostumCols(&stat, params.CustomColumns))
		}
	}
}

func fileGetCustomColsHeader(cols []string) string {
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
		case "tid":
			sb.WriteString(fmt.Sprintf("%-7s", "TID"))
		case "comm":
			sb.WriteString(fmt.Sprintf("%-16s", "COMM"))
		case "reads":
			sb.WriteString(fmt.Sprintf("%-6s", "READS"))
		case "writes":
			sb.WriteString(fmt.Sprintf("%-6s", "WRITES"))
		case "r_kb":
			sb.WriteString(fmt.Sprintf("%-7s", "R_kb"))
		case "w_kb":
			sb.WriteString(fmt.Sprintf("%-7s", "W_kb"))
		case "t":
			sb.WriteString(fmt.Sprintf("%s", "T"))
		case "file":
			sb.WriteString(fmt.Sprintf("%s", "FILE"))
		}
		sb.WriteRune(' ')
	}

	return sb.String()
}

func fileFormatEventCostumCols(stats *types.Stats, cols []string) string {
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
		case "tid":
			sb.WriteString(fmt.Sprintf("%-7d", stats.Tid))
		case "comm":
			sb.WriteString(fmt.Sprintf("%-16s", stats.Comm))
		case "reads":
			sb.WriteString(fmt.Sprintf("%-6d", stats.Reads))
		case "writes":
			sb.WriteString(fmt.Sprintf("%-6d", stats.Writes))
		case "r_kb":
			sb.WriteString(fmt.Sprintf("%-7d", stats.ReadBytes))
		case "w_kb":
			sb.WriteString(fmt.Sprintf("%-7d", stats.WriteBytes))
		case "t":
			sb.WriteString(fmt.Sprintf("%c", stats.FileType))
		case "file":
			sb.WriteString(fmt.Sprintf("%s", stats.Filename))
		}
		sb.WriteRune(' ')
	}

	return sb.String()
}
