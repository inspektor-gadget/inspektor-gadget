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

package trace

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/sigsnoop/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
	"github.com/spf13/cobra"
)

var (
	pid    uint
	sig    string
	failed bool
)

var sigsnoopCmd = &cobra.Command{
	Use:   "signal",
	Short: "Trace signals received by processes",
	RunE: func(cmd *cobra.Command, args []string) error {
		switch params.OutputMode {
		case utils.OutputModeJSON: // don't print any header
		case utils.OutputModeCustomColumns:
			fmt.Println(getCustomSigsnoopColsHeader(params.CustomColumns))
		case utils.OutputModeColumns:
			fmt.Printf("%-16s %-16s %-16s %-16s %-6s %-16s %-9s %-6s %-6s\n",
				"NODE", "NAMESPACE", "POD", "CONTAINER",
				"PID", "COMM", "SIGNAL", "TPID", "RET")
		}

		config := &utils.TraceConfig{
			GadgetName:       "sigsnoop",
			Operation:        "start",
			TraceOutputMode:  "Stream",
			TraceOutputState: "Started",
			CommonFlags:      &params,
			Parameters: map[string]string{
				"signal": sig,
				"pid":    strconv.FormatUint(uint64(pid), 10),
				"failed": strconv.FormatBool(failed),
			},
		}

		err := utils.RunTraceAndPrintStream(config, sigsnoopTransformLine)
		if err != nil {
			return utils.WrapInErrRunGadget(err)
		}

		return nil
	},
}

func init() {
	TraceCmd.AddCommand(sigsnoopCmd)
	utils.AddCommonFlags(sigsnoopCmd, &params)

	sigsnoopCmd.PersistentFlags().UintVarP(
		&pid,
		"pid",
		"",
		0,
		"Show only signal sent by this particular PID",
	)
	sigsnoopCmd.PersistentFlags().StringVarP(
		&sig,
		"signal",
		"",
		"",
		`Trace only this signal (it can be an int like 9 or string beginning with "SIG" like "SIGKILL")`,
	)
	sigsnoopCmd.PersistentFlags().BoolVarP(
		&failed,
		"failed-only",
		"f",
		false,
		`Show only events where the syscall sending a signal failed`,
	)
}

func sigsnoopTransformLine(line string) string {
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
		sb.WriteString(fmt.Sprintf("%-16s %-16s %-16s %-16s %-6d %-16s %-9s %-6d %-6d",
			e.Node, e.Namespace, e.Pod, e.Container, e.Pid, e.Comm,
			e.Signal, e.TargetPid, e.Retval))
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
			case "signal":
				sb.WriteString(fmt.Sprintf("%-9s", e.Signal))
			case "tpid":
				sb.WriteString(fmt.Sprintf("%-6d", e.TargetPid))
			case "ret":
				sb.WriteString(fmt.Sprintf("%-6d", e.Retval))
			}
			sb.WriteRune(' ')
		}
	}

	return sb.String()
}

func getCustomSigsnoopColsHeader(cols []string) string {
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
		case "signal":
			sb.WriteString(fmt.Sprintf("%-9s", "SIGNAL"))
		case "tpid":
			sb.WriteString(fmt.Sprintf("%-6s", "TPID"))
		case "ret":
			sb.WriteString(fmt.Sprintf("%-6s", "RET"))
		}
		sb.WriteRune(' ')
	}

	return sb.String()
}
