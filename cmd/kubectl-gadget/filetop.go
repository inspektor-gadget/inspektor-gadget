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

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/filetop/types"
)

var (
	nodeStats map[string][]types.Stats
	mu        sync.Mutex
	done      bool = false
)

var (
	// arguments
	interval int = 1

	// flags
	maxRows   int
	sortByStr string
	sortBy    types.SortBy
	allFiles  bool
)

var filetopCmd = &cobra.Command{
	Use:   "filetop [interval]",
	Short: "Trace reads and writes by file, with container details",
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error

		nodeStats = make(map[string][]types.Stats)

		if len(args) == 1 {
			interval, err = strconv.Atoi(args[0])
			if err != nil {
				return utils.WrapInErrInvalidArg("<interval>",
					fmt.Errorf("%q is not a valid value", args[0]))
			}
		}

		config := &utils.TraceConfig{
			GadgetName:       "filetop",
			Operation:        "start",
			TraceOutputMode:  "Stream",
			TraceOutputState: "Started",
			CommonFlags:      &params,
			Parameters: map[string]string{
				types.MaxRowsParam:  strconv.Itoa(maxRows),
				types.IntervalParam: strconv.Itoa(interval),
				types.SortByParam:   sortByStr,
				types.AllFilesParam: strconv.FormatBool(allFiles),
			},
		}

		startprint()

		err = utils.RunTraceStreamCallback(config, callback)
		if err != nil {
			return utils.WrapInErrRunGadget(err)
		}

		return nil
	},
	SilenceUsage: true,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		var err error
		sortBy, err = types.ParseSortBy(sortByStr)
		if err != nil {
			return utils.WrapInErrInvalidArg("--sort", err)
		}

		return nil
	},
	Args: cobra.MaximumNArgs(1),
}

func init() {
	filetopCmd.Flags().IntVarP(&maxRows, "maxrows", "r", 20, "Maximum rows to print")
	filetopCmd.Flags().StringVarP(&sortByStr, "sort", "", "rbytes", "Sort column")
	filetopCmd.Flags().BoolVarP(&allFiles, "all-files", "a", false, "Include non-regular file types (sockets, FIFOs, etc)")

	rootCmd.AddCommand(filetopCmd)
	utils.AddCommonFlags(filetopCmd, &params)
}

func callback(line string, node string) {
	mu.Lock()
	defer mu.Unlock()

	var event types.Event

	if err := json.Unmarshal([]byte(line), &event); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s", utils.WrapInErrUnmarshalOutput(err))
		return
	}

	if event.Error != "" {
		fmt.Fprintf(os.Stderr, "Error: failed on node %q: %s", event.Node, event.Error)
		return
	}

	nodeStats[node] = event.Stats
}

func startprint() {
	ticker := time.NewTicker(time.Duration(interval) * time.Second)

	go func() {
		for {
			print()
			_ = <-ticker.C
		}
	}()
}

func print() {
	// sort and print events
	mu.Lock()

	stats := []types.Stats{}
	for _, stat := range nodeStats {
		stats = append(stats, stat...)
	}
	nodeStats = make(map[string][]types.Stats)

	mu.Unlock()

	types.SortStats(stats, sortBy)

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
		if term.IsTerminal(int(os.Stdout.Fd())) {
			utils.ClearScreen()
		} else {
			fmt.Println("")
		}
		fmt.Println(getCustomColsHeader(params.CustomColumns))
		for idx, stat := range stats {
			if idx == maxRows {
				break
			}
			fmt.Println(formatEventCostumCols(&stat, params.CustomColumns))
		}
	}
}

func getCustomColsHeader(cols []string) string {
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

func formatEventCostumCols(stats *types.Stats, cols []string) string {
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
