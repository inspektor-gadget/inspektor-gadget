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

package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	types "github.com/kinvolk/inspektor-gadget/pkg/gadgets/audit-seccomp/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

var auditSeccompCmd = &cobra.Command{
	Use:   "seccomp",
	Short: "Trace syscalls that seccomp sent to the audit log",
	RunE: func(cmd *cobra.Command, args []string) error {
		// print header
		switch params.OutputMode {
		case utils.OutputModeCustomColumns:
			fmt.Println(getCustomAuditSeccompColsHeader(params.CustomColumns))
		case utils.OutputModeColumns:
			fmt.Printf("%-16s %-16s %-16s %-16s %-6s %-6s %-16s %-16s\n",
				"NODE", "NAMESPACE", "POD", "CONTAINER",
				"PCOMM", "PID", "SYSCALL", "CODE")
		}

		config := &utils.TraceConfig{
			GadgetName:       "audit-seccomp",
			Operation:        "start",
			TraceOutputMode:  "Stream",
			TraceOutputState: "Started",
			CommonFlags:      &params,
		}

		err := utils.RunTraceAndPrintStream(config, transformAuditSeccompLine)
		if err != nil {
			return utils.WrapInErrRunGadget(err)
		}

		return nil
	},
}

func init() {
	AuditCmd.AddCommand(auditSeccompCmd)
	utils.AddCommonFlags(auditSeccompCmd, &params)
}

func transformAuditSeccompLine(line string) string {
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
		sb.WriteString(fmt.Sprintf("%-16s %-16s %-16s %-16s %-16s %-6d %-16s %-16s",
			e.Node, e.Namespace, e.Pod, e.Container,
			e.Comm, e.Pid, e.Syscall, e.Code))

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
			case "pcomm":
				sb.WriteString(fmt.Sprintf("%-16s", e.Comm))
			case "pid":
				sb.WriteString(fmt.Sprintf("%-6d", e.Pid))
			case "syscall":
				sb.WriteString(fmt.Sprintf("%-16s", e.Syscall))
			case "code":
				sb.WriteString(fmt.Sprintf("%-16s", e.Code))
			}
			sb.WriteRune(' ')
		}
	}

	return sb.String()
}

func getCustomAuditSeccompColsHeader(cols []string) string {
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
		case "syscall":
			sb.WriteString(fmt.Sprintf("%-16s", "SYSCALL"))
		case "code":
			sb.WriteString(fmt.Sprintf("%-16s", "CODE"))
		}
		sb.WriteRune(' ')
	}

	return sb.String()
}
