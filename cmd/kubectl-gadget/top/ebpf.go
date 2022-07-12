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

	commonutils "github.com/kinvolk/inspektor-gadget/cmd/common/utils"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/top/ebpf/types"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var ebpfNodeStats map[string][]types.Stats

var ebpfSortBy types.SortBy

var ebpfCmd = &cobra.Command{
	Use:   fmt.Sprintf("ebpf [interval=%d]", types.IntervalDefault),
	Short: "Periodically report ebpf runtime stats",
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error

		if params.NamespaceOverridden {
			return commonutils.WrapInErrInvalidArg("--namespace / -n",
				fmt.Errorf("this gadget cannot filter by namespace"))
		}
		if params.Podname != "" {
			return commonutils.WrapInErrInvalidArg("--podname / -p",
				fmt.Errorf("this gadget cannot filter by pod name"))
		}
		if params.Containername != "" {
			return commonutils.WrapInErrInvalidArg("--containername / -c",
				fmt.Errorf("this gadget cannot filter by container name"))
		}
		if len(params.Labels) > 0 {
			return commonutils.WrapInErrInvalidArg("--selector / -l",
				fmt.Errorf("this gadget cannot filter by selector"))
		}

		ebpfNodeStats = make(map[string][]types.Stats)

		if len(args) == 1 {
			outputInterval, err = strconv.Atoi(args[0])
			if err != nil {
				return commonutils.WrapInErrInvalidArg("<interval>",
					fmt.Errorf("%q is not a valid value", args[0]))
			}
		} else {
			outputInterval = types.IntervalDefault
		}

		config := &utils.TraceConfig{
			GadgetName:       "ebpftop",
			Operation:        "start",
			TraceOutputMode:  "Stream",
			TraceOutputState: "Started",
			CommonFlags:      &params,
			Parameters: map[string]string{
				types.MaxRowsParam:  strconv.Itoa(maxRows),
				types.IntervalParam: strconv.Itoa(outputInterval),
				types.SortByParam:   sortBy,
			},
		}

		// when params.Timeout == interval it means the user
		// only wants to run for a given amount of time and print
		// that result.
		singleShot := params.Timeout == outputInterval

		// start print loop if this is not a "single shoot" operation
		if singleShot {
			ebpfPrintHeader()
		} else {
			ebpfStartPrintLoop()
		}

		if err := utils.RunTraceStreamCallback(config, ebpfCallback); err != nil {
			return commonutils.WrapInErrRunGadget(err)
		}

		if singleShot {
			ebpfPrintEvents()
		}

		return nil
	},
	SilenceUsage: true,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		var err error
		ebpfSortBy, err = types.ParseSortBy(sortBy)
		if err != nil {
			return commonutils.WrapInErrInvalidArg("--sort", err)
		}

		return nil
	},
	Args: cobra.MaximumNArgs(1),
}

func init() {
	addTopCommand(ebpfCmd, types.MaxRowsDefault, types.SortBySlice)
}

func ebpfCallback(line string, node string) {
	mutex.Lock()
	defer mutex.Unlock()

	var event types.Event

	if err := json.Unmarshal([]byte(line), &event); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s", commonutils.WrapInErrUnmarshalOutput(err, line))
		return
	}

	if event.Error != "" {
		fmt.Fprintf(os.Stderr, "Error: failed on node %q: %s", event.Node, event.Error)
		return
	}

	ebpfNodeStats[node] = event.Stats
}

func ebpfStartPrintLoop() {
	go func() {
		ticker := time.NewTicker(time.Duration(outputInterval) * time.Second)
		ebpfPrintHeader()
		for {
			_ = <-ticker.C
			ebpfPrintHeader()
			ebpfPrintEvents()
		}
	}()
}

func ebpfPrintHeader() {
	switch params.OutputMode {
	case commonutils.OutputModeColumns:
		if term.IsTerminal(int(os.Stdout.Fd())) {
			utils.ClearScreen()
		} else {
			fmt.Println("")
		}
		fmt.Printf("%-16s %-8s %-16s %-16s %-7s %-20s %12s %10s\n",
			"NODE",
			"PROGID",
			"TYPE",
			"NAME",
			"PID", "COMM",
			"RUNTIME",
			"RUNCOUNT",
		)
	case commonutils.OutputModeCustomColumns:
		if term.IsTerminal(int(os.Stdout.Fd())) {
			utils.ClearScreen()
		} else {
			fmt.Println("")
		}
		fmt.Println(ebpfGetCustomColsHeader(params.CustomColumns))
	}
}

func ebpfPrintEvents() {
	// sort and print events
	mutex.Lock()

	stats := []types.Stats{}
	for node, stat := range ebpfNodeStats {
		for i := range stat {
			stat[i].Node = node
		}
		stats = append(stats, stat...)
	}
	ebpfNodeStats = make(map[string][]types.Stats)

	mutex.Unlock()

	types.SortStats(stats, ebpfSortBy)

	switch params.OutputMode {
	case commonutils.OutputModeColumns:
		for idx, event := range stats {
			if idx == maxRows {
				break
			}
			pid := ""
			comm := ""
			if len(event.Pids) > 0 {
				pid = strconv.Itoa(int(event.Pids[0].Pid))
				comm = event.Pids[0].Comm
			}
			fmt.Printf("%-16s %-8d %-16s %-16s %-7s %-20s %12v %10d\n",
				event.Node,
				event.ProgramID,
				event.Type,
				event.Name,
				pid, comm,
				time.Duration(event.CurrentRuntime),
				event.CurrentRunCount,
			)

		}
	case commonutils.OutputModeJSON:
		b, err := json.Marshal(stats)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s", commonutils.WrapInErrMarshalOutput(err))
			return
		}
		fmt.Println(string(b))
	case commonutils.OutputModeCustomColumns:
		for idx, stat := range stats {
			if idx == maxRows {
				break
			}
			fmt.Println(ebpfFormatEventCustomCols(&stat, params.CustomColumns))
		}
	}
}

func ebpfGetCustomColsHeader(cols []string) string {
	var sb strings.Builder

	for _, col := range cols {
		switch col {
		case "node":
			sb.WriteString(fmt.Sprintf("%-16s", "NODE"))
		case "progid":
			sb.WriteString(fmt.Sprintf("%-8s", "PROGID"))
		case "type":
			sb.WriteString(fmt.Sprintf("%-16s", "TYPE"))
		case "name":
			sb.WriteString(fmt.Sprintf("%-16s", "NAME"))
		case "pid":
			sb.WriteString(fmt.Sprintf("%-7s", "PID"))
		case "comm":
			sb.WriteString(fmt.Sprintf("%-20s", "COMM"))
		case "runtime":
			sb.WriteString(fmt.Sprintf("%12s", "RUNTIME"))
		case "runcount":
			sb.WriteString(fmt.Sprintf("%10s", "RUNCOUNT"))
		case "totalruntime":
			sb.WriteString(fmt.Sprintf("%12s", "T-RUNTIME"))
		case "totalruncount":
			sb.WriteString(fmt.Sprintf("%11s", "T-RUNCOUNT"))
		}
		sb.WriteRune(' ')
	}

	return sb.String()
}

func ebpfFormatEventCustomCols(stats *types.Stats, cols []string) string {
	var sb strings.Builder
	for _, col := range cols {
		switch col {
		case "node":
			sb.WriteString(fmt.Sprintf("%-16s", stats.Node))
		case "progid":
			sb.WriteString(fmt.Sprintf("%-8d", stats.ProgramID))
		case "type":
			sb.WriteString(fmt.Sprintf("%-16s", stats.Type))
		case "name":
			sb.WriteString(fmt.Sprintf("%-16s", stats.Name))
		case "pid":
			pid := ""
			if len(stats.Pids) > 0 {
				pid = fmt.Sprintf("%d", stats.Pids[0].Pid)
			}
			sb.WriteString(fmt.Sprintf("%-7s", pid))
		case "comm":
			comm := ""
			if len(stats.Pids) > 0 {
				comm = stats.Pids[0].Comm
			}
			sb.WriteString(fmt.Sprintf("%-20s", comm))
		case "runtime":
			sb.WriteString(fmt.Sprintf("%12v", time.Duration(stats.CurrentRuntime)))
		case "runcount":
			sb.WriteString(fmt.Sprintf("%10d", stats.CurrentRunCount))
		case "totalruntime":
			sb.WriteString(fmt.Sprintf("%12v", time.Duration(stats.TotalRuntime)))
		case "totalruncount":
			sb.WriteString(fmt.Sprintf("%11d", stats.TotalRunCount))
		}
		sb.WriteRune(' ')
	}
	return sb.String()
}
