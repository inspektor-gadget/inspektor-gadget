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

	"github.com/spf13/cobra"

	commonutils "github.com/kinvolk/inspektor-gadget/cmd/common/utils"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/oomkill/types"
)

type OOMKillParser struct {
	commonutils.BaseParser[types.Event]
}

func newOOMKillCmd() *cobra.Command {
	commonFlags := &utils.CommonFlags{
		OutputConfig: commonutils.OutputConfig{
			// The columns that will be used in case the user does not specify
			// which specific columns they want to print.
			CustomColumns: []string{
				"node",
				"namespace",
				"pod",
				"container",
				"kpid",
				"kcomm",
				"pages",
				"tpid",
				"tcomm",
			},
		},
	}

	cmd := &cobra.Command{
		Use:   "oomkill",
		Short: "Trace when OOM killer is triggered and kills a process",
		RunE: func(cmd *cobra.Command, args []string) error {
			oomkillGadget := &TraceGadget[types.Event]{
				name:        "oomkill",
				commonFlags: commonFlags,
				parser:      NewOOMKillParser(&commonFlags.OutputConfig),
			}

			return oomkillGadget.Run()
		},
	}

	utils.AddCommonFlags(cmd, commonFlags)

	return cmd
}

func NewOOMKillParser(outputConfig *commonutils.OutputConfig) TraceParser[types.Event] {
	columnsWidth := map[string]int{
		"node":      -16,
		"namespace": -16,
		"pod":       -30,
		"container": -16,
		"kpid":      -7,
		"kcomm":     -16,
		"pages":     -6,
		"tpid":      -7,
		"tcomm":     -16,
	}

	return &OOMKillParser{
		BaseParser: commonutils.NewBaseWidthParser[types.Event](columnsWidth, outputConfig),
	}
}

func (p *OOMKillParser) TransformEvent(event *types.Event) string {
	return p.Transform(event, func(event *types.Event) string {
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
			case "kpid":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], event.KilledPid))
			case "kcomm":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.KilledComm))
			case "pages":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], event.Pages))
			case "tpid":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], event.TriggeredPid))
			case "tcomm":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.TriggeredComm))
			default:
				continue
			}

			// Needed when field is larger than the predefined columnsWidth.
			sb.WriteRune(' ')
		}

		return sb.String()
	})
}
