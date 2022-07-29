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

	commonutils "github.com/kinvolk/inspektor-gadget/cmd/common/utils"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/audit/seccomp/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"

	"github.com/spf13/cobra"
)

type SeccompParser struct {
	commonutils.BaseParser[types.Event]
}

func newSeccompCmd() *cobra.Command {
	commonFlags := &utils.CommonFlags{
		OutputConfig: commonutils.OutputConfig{
			// The columns that will be used in case the user does not specify
			// which specific columns they want to print.
			CustomColumns: []string{
				"node",
				"namespace",
				"pod",
				"container",
				"pid",
				"comm",
				"syscall",
				"code",
			},
		},
	}

	columnsWidth := map[string]int{
		"node":      -16,
		"namespace": -16,
		"pod":       -30,
		"container": -16,
		"pid":       -7,
		"comm":      -16,
		"syscall":   -16,
		"code":      -16,
	}

	cmd := &cobra.Command{
		Use:          "seccomp",
		Short:        "Audit syscalls according to the seccomp profile",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			parser := &SeccompParser{
				BaseParser: commonutils.NewBaseWidthParser[types.Event](columnsWidth, &commonFlags.OutputConfig),
			}

			if commonFlags.OutputMode != commonutils.OutputModeJSON {
				fmt.Println(parser.BuildColumnsHeader())
			}

			config := &utils.TraceConfig{
				GadgetName:       "audit-seccomp",
				Operation:        "start",
				TraceOutputMode:  "Stream",
				TraceOutputState: "Started",
				CommonFlags:      commonFlags,
			}

			transformEvent := func(line string) string {
				var e types.Event

				if err := json.Unmarshal([]byte(line), &e); err != nil {
					fmt.Fprintf(os.Stderr, "Error: %s", commonutils.WrapInErrUnmarshalOutput(err, line))
					return ""
				}

				if e.Type != eventtypes.NORMAL {
					commonutils.ManageSpecialEvent(e.Event, commonFlags.Verbose)
					return ""
				}

				return parser.TransformEvent(&e)
			}

			err := utils.RunTraceAndPrintStream(config, transformEvent)
			if err != nil {
				return commonutils.WrapInErrRunGadget(err)
			}

			return nil
		},
	}

	utils.AddCommonFlags(cmd, commonFlags)

	return cmd
}

func (p *SeccompParser) TransformEvent(e *types.Event) string {
	return p.Transform(e, func(e *types.Event) string {
		var sb strings.Builder

		for _, col := range p.OutputConfig.CustomColumns {
			switch col {
			case "node":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], e.Node))
			case "namespace":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], e.Namespace))
			case "pod":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], e.Pod))
			case "container":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], e.Container))
			case "pid":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], e.Pid))
			case "comm":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], e.Comm))
			case "syscall":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], e.Syscall))
			case "code":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], e.Code))
			default:
				continue
			}

			// Needed when field is larger than the predefined columnsWidth.
			sb.WriteRune(' ')
		}

		return sb.String()
	})
}
