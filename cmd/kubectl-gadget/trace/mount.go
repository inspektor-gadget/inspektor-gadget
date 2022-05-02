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
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/mountsnoop/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
	"github.com/spf13/cobra"
)

var mountsnoopCmd = &cobra.Command{
	Use:   "mount",
	Short: "Trace mount and umount system calls",
	RunE: func(cmd *cobra.Command, args []string) error {
		// print header
		switch params.OutputMode {
		case utils.OutputModeCustomColumns:
			fmt.Println(getCustomMountsnoopColsHeader(params.CustomColumns))
		case utils.OutputModeColumns:
			fmt.Printf("%-16s %-16s %-16s %-16s %-16s %-6s %-6s %-10s %s\n",
				"NODE", "NAMESPACE", "POD", "CONTAINER",
				"COMM", "PID", "TID", "MNT_NS", "CALL")
		}

		config := &utils.TraceConfig{
			GadgetName:       "mountsnoop",
			Operation:        "start",
			TraceOutputMode:  "Stream",
			TraceOutputState: "Started",
			CommonFlags:      &params,
		}

		err := utils.RunTraceAndPrintStream(config, mountsnoopTransformLine)
		if err != nil {
			return utils.WrapInErrRunGadget(err)
		}

		return nil
	},
}

func init() {
	TraceCmd.AddCommand(mountsnoopCmd)
	utils.AddCommonFlags(mountsnoopCmd, &params)
}

func getCall(e *types.Event) string {
	switch e.Operation {
	case "mount":
		format := `mount("%s", "%s", "%s", %s, "%s") = %d`
		return fmt.Sprintf(format, e.Source, e.Target, e.Fs, strings.Join(e.Flags, " | "),
			e.Data, e.Retval)
	case "umount":
		format := `umount("%s", %s) = %d`
		return fmt.Sprintf(format, e.Target, strings.Join(e.Flags, " | "), e.Retval)
	}

	return ""
}

// mountsnoopTransformLine is called to transform an event to columns
// format according to the parameters
func mountsnoopTransformLine(line string) string {
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
		sb.WriteString(fmt.Sprintf("%-16s %-16s %-16s %-16s %-16s %-6d %-6d %-10d %s",
			e.Node, e.Namespace, e.Pod, e.Container,
			e.Comm, e.Pid, e.Tid, e.MountNsID, getCall(&e)))
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
			case "tid":
				sb.WriteString(fmt.Sprintf("%-6d", e.Tid))
			case "mnt_ns":
				sb.WriteString(fmt.Sprintf("%-10d", e.MountNsID))
			case "comm":
				sb.WriteString(fmt.Sprintf("%-16s", e.Comm))
			case "op":
				sb.WriteString(fmt.Sprintf("%-6s", e.Operation))
			case "ret":
				sb.WriteString(fmt.Sprintf("%-4d", e.Retval))
			case "lat":
				sb.WriteString(fmt.Sprintf("%-8d", e.Latency/1000))
			case "fs":
				sb.WriteString(fmt.Sprintf("%-16s", e.Fs))
			case "src":
				sb.WriteString(fmt.Sprintf("%-16s", e.Source))
			case "target":
				sb.WriteString(fmt.Sprintf("%-16s", e.Target))
			case "data":
				sb.WriteString(fmt.Sprintf("%-16s", e.Data))
			case "flags":
				sb.WriteString(fmt.Sprintf("%-16s", strings.Join(e.Flags, " | ")))
			case "call":
				sb.WriteString(fmt.Sprintf("%-16s", getCall(&e)))
			}
			sb.WriteRune(' ')
		}
	}

	return sb.String()
}

func getCustomMountsnoopColsHeader(cols []string) string {
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
		case "tid":
			sb.WriteString(fmt.Sprintf("%-6s", "TID"))
		case "mnt_ns":
			sb.WriteString(fmt.Sprintf("%-10s", "MNT_NS"))
		case "comm":
			sb.WriteString(fmt.Sprintf("%-16s", "COMM"))
		case "op":
			sb.WriteString(fmt.Sprintf("%-6s", "OP"))
		case "ret":
			sb.WriteString(fmt.Sprintf("%-4s", "RET"))
		case "lat":
			sb.WriteString(fmt.Sprintf("%-8s", "LAT(us)"))
		case "fs":
			sb.WriteString(fmt.Sprintf("%-16s", "FS"))
		case "src":
			sb.WriteString(fmt.Sprintf("%-16s", "SRC"))
		case "target":
			sb.WriteString(fmt.Sprintf("%-16s", "TARGET"))
		case "data":
			sb.WriteString(fmt.Sprintf("%-16s", "DATA"))
		case "flags":
			sb.WriteString(fmt.Sprintf("%-16s", "FLAGS"))
		case "call":
			sb.WriteString(fmt.Sprintf("%-16s", "CALL"))
		}
		sb.WriteRune(' ')
	}

	return sb.String()
}
