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
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/oomkill/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
	"github.com/spf13/cobra"
)

var oomkillCmd = &cobra.Command{
	Use:   "oomkill",
	Short: "Trace when OOM killer is triggered and kills a process",
	RunE: func(cmd *cobra.Command, args []string) error {
		// print header
		switch params.OutputMode {
		case utils.OutputModeCustomColumns:
			fmt.Println(getCustomOomkillColsHeader(params.CustomColumns))
		case utils.OutputModeColumns:
			fmt.Printf("%-16s %-16s %-16s %-16s %-6s %-16s %-6s %-6s %-16s\n",
				"NODE", "NAMESPACE", "POD", "CONTAINER",
				"KPID", "KCOMM", "PAGES", "TPID", "TCOMM")
		}

		config := &utils.TraceConfig{
			GadgetName:       "oomkill",
			Operation:        "start",
			TraceOutputMode:  "Stream",
			TraceOutputState: "Started",
			CommonFlags:      &params,
		}

		err := utils.RunTraceAndPrintStream(config, oomkillTransformLine)
		if err != nil {
			return utils.WrapInErrRunGadget(err)
		}

		return nil
	},
}

func init() {
	TraceCmd.AddCommand(oomkillCmd)
	utils.AddCommonFlags(oomkillCmd, &params)
}

// oomkillTransformLine is called to transform an event to columns
// format according to the parameters
func oomkillTransformLine(line string) string {
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
		sb.WriteString(fmt.Sprintf("%-16s %-16s %-16s %-16s %-6d %-16s %-6d %-6d %-16s",
			e.Node, e.Namespace, e.Pod, e.Container,
			e.KilledPid, e.KilledComm, e.Pages, e.TriggeredPid, e.TriggeredComm))
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
			case "kpid":
				sb.WriteString(fmt.Sprintf("%-6d", e.KilledPid))
			case "kcomm":
				sb.WriteString(fmt.Sprintf("%-16s", e.KilledComm))
			case "tpid":
				sb.WriteString(fmt.Sprintf("%-6d", e.TriggeredPid))
			case "tcomm":
				sb.WriteString(fmt.Sprintf("%-16s", e.TriggeredComm))
			case "pages":
				sb.WriteString(fmt.Sprintf("%-6d", e.Pages))
			}
			sb.WriteRune(' ')
		}
	}

	return sb.String()
}

func getCustomOomkillColsHeader(cols []string) string {
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
		case "kpid":
			sb.WriteString(fmt.Sprintf("%-6s", "KPID"))
		case "kcomm":
			sb.WriteString(fmt.Sprintf("%-16s", "KCOMM"))
		case "pages":
			sb.WriteString(fmt.Sprintf("%-6s", "PAGES"))
		case "tpid":
			sb.WriteString(fmt.Sprintf("%-6s", "TPID"))
		case "tcomm":
			sb.WriteString(fmt.Sprintf("%-16s", "TCOMM"))
		}
		sb.WriteRune(' ')
	}

	return sb.String()
}
