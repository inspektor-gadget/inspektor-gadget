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
	tcpconnectTypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/tcpconnect/types"
)

type TcpconnectParser struct {
	commonutils.BaseParser[tcpconnectTypes.Event]
}

func newTcpconnectParser(outputConfig *commonutils.OutputConfig, prependColumns []string) TraceParser[tcpconnectTypes.Event] {
	columnsWidth := map[string]int{
		// TODO: Move Kubernetes metadata columns to common/utils.
		"node":      -16,
		"namespace": -16,
		"pod":       -30,
		"container": -16,
		"pid":       -7,
		"comm":      -16,
		"ip":        -3,
		"saddr":     -16,
		"daddr":     -16,
		"dport":     -7,
	}

	if len(outputConfig.CustomColumns) == 0 {
		outputConfig.CustomColumns = GetTcpconnectDefaultColumns()
		if len(prependColumns) != 0 {
			outputConfig.CustomColumns = append(prependColumns, outputConfig.CustomColumns...)
		}
	}

	return &TcpconnectParser{
		BaseParser: commonutils.NewBaseWidthParser[tcpconnectTypes.Event](columnsWidth, outputConfig),
	}
}

func NewTcpconnectParserWithK8sInfo(outputConfig *commonutils.OutputConfig) TraceParser[tcpconnectTypes.Event] {
	return newTcpconnectParser(outputConfig, commonutils.GetKubernetesColumns())
}

func NewTcpconnectParserWithRuntimeInfo(outputConfig *commonutils.OutputConfig) TraceParser[tcpconnectTypes.Event] {
	return newTcpconnectParser(outputConfig, commonutils.GetContainerRuntimeColumns())
}

func (p *TcpconnectParser) TransformIntoColumns(event *tcpconnectTypes.Event) string {
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
		case "dport":
			sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], event.Dport))
		default:
			continue
		}

		// Needed when field is larger than the predefined columnsWidth.
		sb.WriteRune(' ')
	}

	return sb.String()
}

func GetTcpconnectDefaultColumns() []string {
	// The columns that will be used in case the user does not specify which
	// specific columns they want to print through OutputConfig.
	return []string{
		"pid",
		"comm",
		"ip",
		"saddr",
		"daddr",
		"dport",
	}
}

func NewTcpconnectCmd(runCmd func(*cobra.Command, []string) error) *cobra.Command {
	return &cobra.Command{
		Use:   "tcpconnect",
		Short: "Trace connect system calls",
		RunE:  runCmd,
	}
}
