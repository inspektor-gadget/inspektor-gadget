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
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/opensnoop/types"

	"github.com/spf13/cobra"
)

type OpenParser struct {
	BaseTraceParser
}

func newOpenCmd() *cobra.Command {
	commonFlags := &utils.CommonFlags{
		OutputConfig: utils.OutputConfig{
			// The columns that will be used in case the user does not specify
			// which specific columns they want to print.
			CustomColumns: []string{
				"node",
				"namespace",
				"pod",
				"container",
				"pid",
				"comm",
				"fd",
				"err",
				"path",
			},
		},
	}

	cmd := &cobra.Command{
		Use:   "open",
		Short: "Trace open system calls",
		RunE: func(cmd *cobra.Command, args []string) error {
			openGadget := &TraceGadget[types.Event]{
				name:        "opensnoop",
				commonFlags: commonFlags,
				parser:      NewOpenParser(&commonFlags.OutputConfig),
			}

			return openGadget.Run()
		},
	}

	utils.AddCommonFlags(cmd, commonFlags)

	return cmd
}

func NewOpenParser(outputConfig *utils.OutputConfig) TraceParser[types.Event] {
	columnsWidth := map[string]int{
		"node":      -16,
		"namespace": -16,
		"pod":       -30,
		"container": -16,
		"pid":       -7,
		"comm":      -16,
		"fd":        -3,
		"err":       -3,
		"path":      -24,
	}

	return &OpenParser{
		BaseTraceParser: BaseTraceParser{
			columnsWidth: columnsWidth,
			outputConfig: outputConfig,
		},
	}
}

func (p *OpenParser) TransformEvent(event *types.Event, requestedColumns []string) string {
	var sb strings.Builder

	for _, col := range requestedColumns {
		switch col {
		case "node":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.Node))
		case "namespace":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.Namespace))
		case "pod":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.Pod))
		case "container":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.Container))
		case "pid":
			sb.WriteString(fmt.Sprintf("%*d", p.columnsWidth[col], event.Pid))
		case "comm":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.Comm))
		case "fd":
			sb.WriteString(fmt.Sprintf("%*d", p.columnsWidth[col], event.Fd))
		case "err":
			sb.WriteString(fmt.Sprintf("%*d", p.columnsWidth[col], event.Err))
		case "path":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.Path))
		}

		// Needed when field is larger than the predefined columnsWidth.
		sb.WriteRune(' ')
	}

	return sb.String()
}
