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
	"encoding/json"
	"fmt"
	"os"
	"strings"

	commonutils "github.com/kinvolk/inspektor-gadget/cmd/common/utils"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/opensnoop/types"

	"github.com/spf13/cobra"
)

type OpenParser struct {
	commonutils.BaseParser[types.Event]
}

func newOpenCmd() *cobra.Command {
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

func NewOpenParser(outputConfig *commonutils.OutputConfig) TraceParser[types.Event] {
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
		BaseParser: commonutils.NewBaseWidthParser[types.Event](columnsWidth, outputConfig),
	}
}

func (p *OpenParser) TransformEvent(event *types.Event) string {
	var sb strings.Builder

	switch p.OutputConfig.OutputMode {
	case commonutils.OutputModeJSON:
		b, err := json.Marshal(event)
		if err != nil {
			fmt.Fprint(os.Stderr, fmt.Sprint(commonutils.WrapInErrMarshalOutput(err)))
			return ""
		}
		sb.WriteString(string(b))
	case commonutils.OutputModeColumns:
		fallthrough
	case commonutils.OutputModeCustomColumns:
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
			case "fd":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], event.Fd))
			case "err":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], event.Err))
			case "path":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.Path))
			}

			// Needed when field is larger than the predefined columnsWidth.
			sb.WriteRune(' ')
		}
	}

	return sb.String()
}
