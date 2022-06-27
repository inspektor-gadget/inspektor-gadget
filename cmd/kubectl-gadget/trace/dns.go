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

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/dns/types"

	"github.com/spf13/cobra"
)

type DNSParser struct {
	BaseTraceParser
}

func newDNSCmd() *cobra.Command {
	commonFlags := &utils.CommonFlags{
		OutputConfig: utils.OutputConfig{
			// The columns that will be used in case the user does not specify
			// which specific columns they want to print.
			CustomColumns: []string{
				"node",
				"namespace",
				"pod",
				"type",
				"qtype",
				"name",
			},
		},
	}

	cmd := &cobra.Command{
		Use:   "dns",
		Short: "Trace DNS requests",
		RunE: func(cmd *cobra.Command, args []string) error {
			dnsGadget := &TraceGadget[types.Event]{
				name:        "dns",
				commonFlags: commonFlags,
				parser:      NewDNSParser(&commonFlags.OutputConfig),
			}

			return dnsGadget.Run()
		},
	}

	utils.AddCommonFlags(cmd, commonFlags)

	return cmd
}

func NewDNSParser(outputConfig *utils.OutputConfig) TraceParser[types.Event] {
	columnsWidth := map[string]int{
		"node":      -16,
		"namespace": -16,
		"pod":       -30,
		"type":      -9,
		"qtype":     -10,
		"name":      -24,
	}

	return &DNSParser{
		BaseTraceParser: BaseTraceParser{
			columnsWidth: columnsWidth,
			outputConfig: outputConfig,
		},
	}
}

func (p *DNSParser) TransformEvent(event *types.Event, requestedColumns []string) string {
	var sb strings.Builder

	for _, col := range requestedColumns {
		switch col {
		case "node":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.Node))
		case "namespace":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.Namespace))
		case "pod":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.Pod))
		case "type":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.PktType))
		case "qtype":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.QType))
		case "name":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.DNSName))
		}

		// Needed when field is larger than the predefined columnsWidth.
		sb.WriteRune(' ')
	}

	return sb.String()
}
