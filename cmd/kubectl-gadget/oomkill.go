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
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/oomkill/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
	"github.com/spf13/cobra"
)

var oomkillCmd = &cobra.Command{
	Use:   "oomkill",
	Short: "Trace when OOM killer is triggered and kills a process",
	RunE: func(cmd *cobra.Command, args []string) error {
		var transform func(string) string
		switch params.OutputMode {
		case utils.OutputModeJson: // don't print any header
		case utils.OutputModeCustomColumns:
			fmt.Println(getCustomOomkillColsHeader(params.CustomColumns))
			transform = formatEventOomkillCostumCols
		case utils.OutputModeColumns:
			transform = oomkillTransformLine

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

		return utils.RunTraceAndPrintStream(config, transform)
	},
}

func init() {
	rootCmd.AddCommand(oomkillCmd)
	utils.AddCommonFlags(oomkillCmd, &params)
}

func oomkillTransformLine(line string) string {
	var sb strings.Builder
	var e types.Event

	if err := json.Unmarshal([]byte(line), &e); err != nil {
		fmt.Fprintf(os.Stderr, "error unmarshalling json: %s", err)
		return ""
	}

	switch e.Type {
	case eventtypes.NORMAL:
		sb.WriteString(fmt.Sprintf("%-16s %-16s %-16s %-16s %-6d %-16s %-6d %-6d %-16s",
			e.Node, e.Namespace, e.Pod, e.Container,
			e.KilledPid, e.KilledComm, e.Pages, e.TriggeredPid, e.TriggeredComm))

		return sb.String()
	case eventtypes.ERR:
		fmt.Fprintf(os.Stderr, "error from node %s: %s", e.Node, e.Message)
		return ""
	}

	return ""
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

func formatEventOomkillCostumCols(line string) string {
	var sb strings.Builder

	var event types.Event
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		var msg string
		if err2 := json.Unmarshal([]byte(line), &msg); err2 == nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", line)
			return ""
		}

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
		case "kpid":
			sb.WriteString(fmt.Sprintf("%-6d", event.KilledPid))
		case "kcomm":
			sb.WriteString(fmt.Sprintf("%-16s", event.KilledComm))
		case "tpid":
			sb.WriteString(fmt.Sprintf("%-6d", event.TriggeredPid))
		case "tcomm":
			sb.WriteString(fmt.Sprintf("%-16s", event.TriggeredComm))
		case "pages":
			sb.WriteString(fmt.Sprintf("%-6d", event.Pages))
		}
		sb.WriteRune(' ')
	}

	return sb.String()
}
