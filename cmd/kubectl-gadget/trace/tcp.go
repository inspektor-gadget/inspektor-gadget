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
	"fmt"
	"strings"

	commonutils "github.com/kinvolk/inspektor-gadget/cmd/common/utils"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/tcptracer/types"

	"github.com/spf13/cobra"
)

type TCPParser struct {
	commonutils.BaseParser
}

func newTCPCmd() *cobra.Command {
	commonFlags := &utils.CommonFlags{
		OutputConfig: commonutils.OutputConfig{
			// The columns that will be used in case the user does not specify
			// which specific columns they want to print.
			CustomColumns: []string{
				"node",
				"namespace",
				"pod",
				"container",
				"t",
				"pid",
				"comm",
				"ip",
				"saddr",
				"daddr",
				"sport",
				"dport",
			},
		},
	}

	cmd := &cobra.Command{
		Use:   "tcp",
		Short: "Trace tcp connect, accept and close",
		RunE: func(cmd *cobra.Command, args []string) error {
			tcpGadget := &TraceGadget[types.Event]{
				name:        "tcptracer",
				commonFlags: commonFlags,
				parser:      NewTCPParser(&commonFlags.OutputConfig),
			}

			return tcpGadget.Run()
		},
	}

	utils.AddCommonFlags(cmd, commonFlags)

	return cmd
}

func NewTCPParser(outputConfig *commonutils.OutputConfig) TraceParser[types.Event] {
	columnsWidth := map[string]int{
		"node":      -16,
		"namespace": -16,
		"pod":       -30,
		"container": -16,
		"t":         -2,
		"pid":       -7,
		"comm":      -16,
		"ip":        -3,
		"saddr":     -16,
		"daddr":     -16,
		"sport":     -7,
		"dport":     -7,
	}

	return &TCPParser{
		BaseParser: commonutils.BaseParser{
			ColumnsWidth: columnsWidth,
			OutputConfig: outputConfig,
		},
	}
}

func getOperationShort(operation string) string {
	operations := map[string]string{
		"accept":  "A",
		"connect": "C",
		"close":   "X",
		"unknown": "U",
	}

	if op, ok := operations[operation]; ok {
		return op
	}

	return "U"
}

func (p *TCPParser) TransformEvent(event *types.Event, requestedColumns []string) string {
	var sb strings.Builder

	for _, col := range requestedColumns {
		switch col {
		case "node":
			sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.Node))
		case "namespace":
			sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.Namespace))
		case "pod":
			sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.Pod))
		case "container":
			sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.Container))
		case "t":
			sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], getOperationShort(event.Operation)))
		case "pid":
			sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], event.Pid))
		case "comm":
			sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.Comm))
		case "ip":
			sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], event.IPVersion))
		case "saddr":
			sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.Saddr))
		case "daddr":
			sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.Daddr))
		case "sport":
			sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], event.Sport))
		case "dport":
			sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], event.Dport))
		}

		// Needed when field is larger than the predefined columnsWidth.
		sb.WriteRune(' ')
	}

	return sb.String()
}
