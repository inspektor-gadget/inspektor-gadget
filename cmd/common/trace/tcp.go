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

	"github.com/spf13/cobra"

	commonutils "github.com/kinvolk/inspektor-gadget/cmd/common/utils"
	tcpTypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/tcp/types"
)

type TCPParser struct {
	commonutils.BaseParser[tcpTypes.Event]
}

func newTCPParser(outputConfig *commonutils.OutputConfig, prependColumns []string) TraceParser[tcpTypes.Event] {
	columnsWidth := map[string]int{
		// TODO: Move Kubernetes metadata columns to common/utils.
		"node":      -16,
		"namespace": -16,
		"pod":       -30,
		"container": -16,
		"t":         -2,
		"pid":       -7,
		"comm":      -16,
		"ip":        -3,
		"saddr":     -22,
		"daddr":     -22,
		"sport":     -7,
		"dport":     -7,
	}

	if len(outputConfig.CustomColumns) == 0 {
		outputConfig.CustomColumns = GetTCPDefaultColumns()
		if len(prependColumns) != 0 {
			outputConfig.CustomColumns = append(prependColumns, outputConfig.CustomColumns...)
		}
	}

	return &TCPParser{
		BaseParser: commonutils.NewBaseWidthParser[tcpTypes.Event](columnsWidth, outputConfig),
	}
}

func NewTCPParserWithK8sInfo(outputConfig *commonutils.OutputConfig) TraceParser[tcpTypes.Event] {
	return newTCPParser(outputConfig, commonutils.GetKubernetesColumns())
}

func NewTCPParserWithRuntimeInfo(outputConfig *commonutils.OutputConfig) TraceParser[tcpTypes.Event] {
	return newTCPParser(outputConfig, commonutils.GetContainerRuntimeColumns())
}

func NewTCPParser(outputConfig *commonutils.OutputConfig) TraceParser[tcpTypes.Event] {
	return newTCPParser(outputConfig, nil)
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

func (p *TCPParser) TransformEvent(event *tcpTypes.Event) string {
	return p.Transform(event, func(event *tcpTypes.Event) string {
		var sb strings.Builder

		for _, col := range p.OutputConfig.CustomColumns {
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
			default:
				continue
			}

			// Needed when field is larger than the predefined columnsWidth.
			sb.WriteRune(' ')
		}

		return sb.String()
	})
}

func GetTCPDefaultColumns() []string {
	// The columns that will be used in case the user does not specify which
	// specific columns they want to print through OutputConfig.
	return []string{
		"t",
		"pid",
		"comm",
		"ip",
		"saddr",
		"daddr",
		"sport",
		"dport",
	}
}

func NewTCPCmd(runCmd func(*cobra.Command, []string) error) *cobra.Command {
	return &cobra.Command{
		Use:   "tcp",
		Short: "Trace tcp connect, accept and close",
		RunE:  runCmd,
	}
}
