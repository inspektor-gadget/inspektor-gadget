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
	"fmt"
	"strings"

	commonutils "github.com/kinvolk/inspektor-gadget/cmd/common/utils"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/network/types"

	"github.com/spf13/cobra"
)

type NetworkParser struct {
	commonutils.BaseParser
}

func newNetworkCmd() *cobra.Command {
	commonFlags := &utils.CommonFlags{
		OutputConfig: commonutils.OutputConfig{
			// The columns that will be used in case the user does not specify
			// which specific columns they want to print.
			CustomColumns: []string{
				"node",
				"namespace",
				"pod",
				"type",
				"proto",
				"port",
				"remote",
			},
		},
	}

	cmd := &cobra.Command{
		Use:   "network",
		Short: "Trace network streams",
		RunE: func(cmd *cobra.Command, args []string) error {
			networkGadget := &TraceGadget[types.Event]{
				name:        "network-graph",
				commonFlags: commonFlags,
				parser:      NewNetworkParser(&commonFlags.OutputConfig),
			}

			return networkGadget.Run()
		},
	}

	utils.AddCommonFlags(cmd, commonFlags)

	return cmd
}

func NewNetworkParser(outputConfig *commonutils.OutputConfig) TraceParser[types.Event] {
	columnsWidth := map[string]int{
		"node":      -16,
		"namespace": -16,
		"pod":       -30,
		"type":      -9,
		"proto":     -6,
		"port":      -7,
		"remote":    -30,
	}

	return &NetworkParser{
		BaseParser: commonutils.NewBaseWidthParser(columnsWidth, outputConfig),
	}
}

func (p *NetworkParser) TransformEvent(event *types.Event) string {
	var sb strings.Builder

	if event.Pod == "" {
		// ignore events on host netns for now
		return ""
	}

	remote := ""
	switch event.RemoteKind {
	case "pod":
		remote = fmt.Sprintf("pod %s/%s", event.RemotePodNamespace, event.RemotePodName)
	case "svc":
		remote = fmt.Sprintf("svc %s/%s", event.RemoteSvcNamespace, event.RemoteSvcName)
	case "other":
		remote = fmt.Sprintf("endpoint %s", event.RemoteOther)
	default:
		remote = fmt.Sprintf("? %s", event.Debug)
	}

	for _, col := range p.OutputConfig.CustomColumns {
		switch col {
		case "node":
			sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.Node))
		case "namespace":
			sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.Namespace))
		case "pod":
			sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.Pod))
		case "type":
			sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.PktType))
		case "proto":
			sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.Proto))
		case "port":
			sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], event.Port))
		case "remote":
			sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], remote))
		}

		// Needed when field is larger than the predefined columnsWidth.
		sb.WriteRune(' ')
	}

	return sb.String()
}
