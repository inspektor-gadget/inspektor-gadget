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
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/capabilities/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
	"github.com/spf13/cobra"
)

var capabilitiesCmd = &cobra.Command{
	Use:   "capabilities",
	Short: "Trace security capability checks",
	RunE: func(cmd *cobra.Command, args []string) error {
		// print header
		switch params.OutputMode {
		case utils.OutputModeCustomColumns:
			fmt.Println(getCustomOpensnoopColsHeader(params.CustomColumns))
		case utils.OutputModeColumns:
			fmt.Printf("%-16s %-16s %-16s %-16s %-6s %-6s %-16s %-4s %-16s %-6s\n",
				"NODE", "NAMESPACE", "POD", "CONTAINER",
				"UID", "PID", "COMM", "CAP", "NAME", "AUDIT")
		}

		config := &utils.TraceConfig{
			GadgetName:       "capabilities",
			Operation:        "start",
			TraceOutputMode:  "Stream",
			TraceOutputState: "Started",
			CommonFlags:      &params,
		}

		err := utils.RunTraceAndPrintStream(config, capabilitiesTransformLine)
		if err != nil {
			return utils.WrapInErrRunGadget(err)
		}

		return nil
	},
}

func init() {
	TraceCmd.AddCommand(capabilitiesCmd)
	utils.AddCommonFlags(capabilitiesCmd, &params)
}

// capabilitiesTransformLine is called to transform an event to columns
// format according to the parameters
func capabilitiesTransformLine(line string) string {
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
		sb.WriteString(fmt.Sprintf("%-16s %-16s %-16s %-16s %-6d %-6d %-16s %-4d %-16s %-6d",
			e.Node, e.Namespace, e.Pod, e.Container,
			e.UID, e.Pid, e.Comm, e.Cap, e.CapName, e.Audit))
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
			case "uid":
				sb.WriteString(fmt.Sprintf("%-6d", e.UID))
			case "comm":
				sb.WriteString(fmt.Sprintf("%-16s", e.Comm))
			case "cap":
				sb.WriteString(fmt.Sprintf("%-4d", e.Cap))
			case "name":
				sb.WriteString(fmt.Sprintf("%-16s", e.CapName))
			case "audit":
				sb.WriteString(fmt.Sprintf("%-6d", e.Audit))
			}
			sb.WriteRune(' ')
		}
	}

	return sb.String()
}

func getCustomCapabilitiesColsHeader(cols []string) string {
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
		case "uid":
			sb.WriteString(fmt.Sprintf("%-6s", "UID"))
		case "comm":
			sb.WriteString(fmt.Sprintf("%-16s", "COMM"))
		case "cap":
			sb.WriteString(fmt.Sprintf("%-4s", "CAP"))
		case "name":
			sb.WriteString(fmt.Sprintf("%-16s", "NAME"))
		case "audit":
			sb.WriteString(fmt.Sprintf("%-6s", "AUDIT"))
		}
		sb.WriteRune(' ')
	}

	return sb.String()
}
