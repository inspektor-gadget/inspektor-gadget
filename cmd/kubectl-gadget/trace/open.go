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

package trace

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/opensnoop/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
	"github.com/spf13/cobra"
)

var opensnoopCmd = &cobra.Command{
	Use:   "open",
	Short: "Trace open system calls",
	RunE: func(cmd *cobra.Command, args []string) error {
		// print header
		switch params.OutputMode {
		case utils.OutputModeCustomColumns:
			fmt.Println(getCustomOpensnoopColsHeader(params.CustomColumns))
		case utils.OutputModeColumns:
			fmt.Printf("%-16s %-16s %-16s %-16s %-6s %-16s %-3s %3s %s\n",
				"NODE", "NAMESPACE", "POD", "CONTAINER",
				"PID", "COMM", "FD", "ERR", "PATH")
		}

		config := &utils.TraceConfig{
			GadgetName:       "opensnoop",
			Operation:        "start",
			TraceOutputMode:  "Stream",
			TraceOutputState: "Started",
			CommonFlags:      &params,
		}

		err := utils.RunTraceAndPrintStream(config, opensnoopTransformLine)
		if err != nil {
			return utils.WrapInErrRunGadget(err)
		}

		return nil
	},
}

func init() {
	TraceCmd.AddCommand(opensnoopCmd)
	utils.AddCommonFlags(opensnoopCmd, &params)
}

// opensnoopTransformLine is called to transform an event to columns
// format according to the parameters
func opensnoopTransformLine(line string) string {
	var sb strings.Builder
	var e types.Event

	if err := json.Unmarshal([]byte(line), &e); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s", utils.WrapInErrUnmarshalOutput(err, line))
		return ""
	}

	if e.Type == eventtypes.ERR || e.Type == eventtypes.WARN ||
		e.Type == eventtypes.DEBUG || e.Type == eventtypes.INFO {
		fmt.Fprintf(os.Stderr, "%s: node %q: %s", e.Type, e.Node, e.Message)
		return ""
	}

	if e.Type != eventtypes.NORMAL {
		return ""
	}

	switch params.OutputMode {
	case utils.OutputModeColumns:
		sb.WriteString(fmt.Sprintf("%-16s %-16s %-16s %-16s %-6d %-16s %-3d %3d %s",
			e.Node, e.Namespace, e.Pod, e.Container,
			e.Pid, e.Comm, e.Fd, e.Err, e.Path))
	case utils.OutputModeCustomColumns:
		for _, col := range params.CustomColumns {
			switch col {
			case "node":
				sb.WriteString(fmt.Sprintf("%-16s", e.Node))
			case "namespace":
				sb.WriteString(fmt.Sprintf("%-16s", e.Namespace))
			case "pod":
				sb.WriteString(fmt.Sprintf("%-16s", e.Pod))
			case "container":
				sb.WriteString(fmt.Sprintf("%-16s", e.Container))
			case "pid":
				sb.WriteString(fmt.Sprintf("%-6d", e.Pid))
			case "comm":
				sb.WriteString(fmt.Sprintf("%-16s", e.Comm))
			case "fd":
				sb.WriteString(fmt.Sprintf("%-2d", e.Fd))
			case "err":
				sb.WriteString(fmt.Sprintf("%-3d", e.Err))
			case "path":
				sb.WriteString(fmt.Sprintf("%-24s", e.Path))
			}
			sb.WriteRune(' ')
		}
	}

	return sb.String()
}

func getCustomOpensnoopColsHeader(cols []string) string {
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
			sb.WriteString(fmt.Sprintf("%-6s", "PID"))
		case "comm":
			sb.WriteString(fmt.Sprintf("%-16s", "COMM"))
		case "fd":
			sb.WriteString(fmt.Sprintf("%-3s", "FD"))
		case "err":
			sb.WriteString(fmt.Sprintf("%-3s", "ERR"))
		case "path":
			sb.WriteString(fmt.Sprintf("%-24s", "PATH"))
		}
		sb.WriteRune(' ')
	}

	return sb.String()
}
