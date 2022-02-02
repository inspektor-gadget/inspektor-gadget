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
	"strings"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/execsnoop/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
	"github.com/spf13/cobra"
)

var execsnoopCmd = &cobra.Command{
	Use:   "execsnoop",
	Short: "Trace new processes",
	RunE: func(cmd *cobra.Command, args []string) error {
		var transform func(string) string
		switch params.OutputMode {
		case utils.OutputModeJson: // don't print any header
		case utils.OutputModeCustomColumns:
			fmt.Println(getCustomExecsnoopColsHeader(params.CustomColumns))
			transform = formatEventExecsnoopCostumCols
		case utils.OutputModeColumns:
			transform = execsnoopTransformLine

			fmt.Printf("%-16s %-16s %-16s %-16s %-16s %-6s %-6s %3s %s\n",
				"NODE", "NAMESPACE", "POD", "CONTAINER",
				"PCOMM", "PID", "PPID", "RET", "ARGS")
		}

		config := &utils.TraceConfig{
			GadgetName:       "execsnoop",
			Operation:        "start",
			TraceOutputMode:  "Stream",
			TraceOutputState: "Started",
			CommonFlags:      &params,
		}

		err := utils.RunTraceAndPrintStream(config, transform)
		if err != nil {
			return fmt.Errorf("failed to run tracer: %w", err)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(execsnoopCmd)
	utils.AddCommonFlags(execsnoopCmd, &params)
}

func execsnoopTransformLine(line string) string {
	var sb strings.Builder
	var e types.Event

	if err := json.Unmarshal([]byte(line), &e); err != nil {
		fmt.Fprintf(os.Stderr, "error unmarshalling json: %s", err)
		return ""
	}

	switch e.Type {
	case eventtypes.NORMAL:
		sb.WriteString(fmt.Sprintf("%-16s %-16s %-16s %-16s %-16s %-6d %-6d %3d",
			e.Node, e.Namespace, e.Pod, e.Container,
			e.Comm, e.Pid, e.Ppid, e.Retval))

		for _, arg := range e.Args {
			sb.WriteString(" " + arg)
		}

		return sb.String()
	case eventtypes.ERR:
		fmt.Fprintf(os.Stderr, "error from node %s: %s", e.Node, e.Message)
		return ""
	}

	return ""
}

func getCustomExecsnoopColsHeader(cols []string) string {
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
		case "pcomm":
			sb.WriteString(fmt.Sprintf("%-16s", "PCOMM"))
		case "pid":
			sb.WriteString(fmt.Sprintf("%-6s", "PID"))
		case "ppid":
			sb.WriteString(fmt.Sprintf("%-6s", "PPID"))
		case "ret":
			sb.WriteString(fmt.Sprintf("%-3s", "RET"))
		case "args":
			sb.WriteString(fmt.Sprintf("%-24s", "ARGS"))
		}
		sb.WriteRune(' ')
	}

	return sb.String()
}

func formatEventExecsnoopCostumCols(line string) string {
	var sb strings.Builder

	var event types.Event
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		fmt.Fprintf(os.Stderr, "error unmarshalling json: %s", err)
		return ""
	}

	for _, col := range params.CustomColumns {
		switch col {
		case "node":
			sb.WriteString(fmt.Sprintf("%-16s", event.Node))
		case "namespace":
			sb.WriteString(fmt.Sprintf("%-16s", event.Namespace))
		case "pod":
			sb.WriteString(fmt.Sprintf("%-16s", event.Pod))
		case "container":
			sb.WriteString(fmt.Sprintf("%-16s", event.Container))
		case "pcomm":
			sb.WriteString(fmt.Sprintf("%-16s", event.Comm))
		case "pid":
			sb.WriteString(fmt.Sprintf("%-6d", event.Pid))
		case "ppid":
			sb.WriteString(fmt.Sprintf("%-6d", event.Ppid))
		case "ret":
			sb.WriteString(fmt.Sprintf("%-3d", event.Retval))
		case "args":
			for _, arg := range event.Args {
				sb.WriteString(fmt.Sprintf("%s ", arg))
			}
		}
		sb.WriteRune(' ')
	}

	return sb.String()
}
