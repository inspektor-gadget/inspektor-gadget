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

package trace

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/tcptracer/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
	"github.com/spf13/cobra"
)

var tcptracerCmd = &cobra.Command{
	Use:   "tcp",
	Short: "Trace tcp connect, accept and close",
	RunE: func(cmd *cobra.Command, args []string) error {
		// print header
		switch params.OutputMode {
		case utils.OutputModeCustomColumns:
			fmt.Println(getCustomTcptracerColsHeader(params.CustomColumns))
		case utils.OutputModeColumns:
			fmt.Printf("%-16s %-16s %-16s %-16s %s %-6s %-16s %-3s %-16s %-16s %-7s %-7s\n",
				"NODE", "NAMESPACE", "POD", "CONTAINER",
				"T", "PID", "COMM", "IP", "SADDR", "DADDR", "SPORT", "DPORT")
		}

		config := &utils.TraceConfig{
			GadgetName:       "tcptracer",
			Operation:        "start",
			TraceOutputMode:  "Stream",
			TraceOutputState: "Started",
			CommonFlags:      &params,
		}

		err := utils.RunTraceAndPrintStream(config, tcptracerTransformLine)
		if err != nil {
			return utils.WrapInErrRunGadget(err)
		}

		return nil
	},
}

func init() {
	TraceCmd.AddCommand(tcptracerCmd)
	utils.AddCommonFlags(tcptracerCmd, &params)
}

var operations = map[string]string{
	"accept":  "A",
	"connect": "C",
	"close":   "X",
	"unknown": "U",
}

func getOperationShort(operation string) string {
	if op, ok := operations[operation]; ok {
		return op
	}

	return "U"
}

// tcptracerTransformLine is called to transform an event to columns
// format according to the parameters
func tcptracerTransformLine(line string) string {
	var sb strings.Builder
	var e types.Event

	if err := json.Unmarshal([]byte(line), &e); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s", utils.WrapInErrUnmarshalOutput(err, line))
		return ""
	}

	if e.Type == eventtypes.ERR || e.Type == eventtypes.WARN ||
		e.Type == eventtypes.DEBUG || e.Type == eventtypes.INFO {
		fmt.Fprintf(os.Stderr, "%s: node %s: %s", e.Type, e.Node, e.Message)
		return ""
	}

	if e.Type != eventtypes.NORMAL {
		return ""
	}

	switch params.OutputMode {
	case utils.OutputModeColumns:
		sb.WriteString(fmt.Sprintf("%-16s %-16s %-16s %-16s %s %-6d %-16s %-3d %-16s %-16s %-7d %-7d",
			e.Node, e.Namespace, e.Pod, e.Container,
			getOperationShort(e.Operation), e.Pid, e.Comm, e.IPVersion,
			e.Saddr, e.Daddr, e.Sport, e.Dport))
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
			case "t":
				sb.WriteString(fmt.Sprintf("%s", getOperationShort(e.Operation)))
			case "pid":
				sb.WriteString(fmt.Sprintf("%-6d", e.Pid))
			case "comm":
				sb.WriteString(fmt.Sprintf("%-16s", e.Comm))
			case "ip":
				sb.WriteString(fmt.Sprintf("%-3d", e.IPVersion))
			case "saddr":
				sb.WriteString(fmt.Sprintf("%-16s", e.Saddr))
			case "daddr":
				sb.WriteString(fmt.Sprintf("%-16s", e.Daddr))
			case "sport":
				sb.WriteString(fmt.Sprintf("%-7d", e.Sport))
			case "dport":
				sb.WriteString(fmt.Sprintf("%-7d", e.Dport))
			}
			sb.WriteRune(' ')
		}
	}

	return sb.String()
}

func getCustomTcptracerColsHeader(cols []string) string {
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
		case "t":
			sb.WriteString(fmt.Sprintf("%s", "T"))
		case "pid":
			sb.WriteString(fmt.Sprintf("%-6s", "PID"))
		case "comm":
			sb.WriteString(fmt.Sprintf("%-16s", "COMM"))
		case "ip":
			sb.WriteString(fmt.Sprintf("%-3s", "IP"))
		case "saddr":
			sb.WriteString(fmt.Sprintf("%-16s", "SADDR"))
		case "daddr":
			sb.WriteString(fmt.Sprintf("%-16s", "DADDR"))
		case "sport":
			sb.WriteString(fmt.Sprintf("%-7s", "SPORT"))
		case "dport":
			sb.WriteString(fmt.Sprintf("%-7s", "DPORT"))
		}
		sb.WriteRune(' ')
	}

	return sb.String()
}
