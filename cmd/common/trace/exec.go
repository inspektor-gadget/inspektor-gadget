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
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/exec/types"
)

type ExecParser struct {
	commonutils.BaseParser[types.Event]
}

func newExecParser(outputConfig *commonutils.OutputConfig, prependColumns []string) TraceParser[types.Event] {
	columnsWidth := map[string]int{
		// TODO: Move Kubernetes metadata columns to common/utils.
		"node":      -16,
		"namespace": -16,
		"pod":       -30,
		"container": -16,
		"pid":       -7,
		"ppid":      -7,
		"pcomm":     -16,
		"ret":       -4,
		"args":      -24,
	}

	if len(outputConfig.CustomColumns) == 0 {
		outputConfig.CustomColumns = GetExecDefaultColumns()
		if len(prependColumns) != 0 {
			outputConfig.CustomColumns = append(prependColumns, outputConfig.CustomColumns...)
		}
	}

	return &ExecParser{
		BaseParser: commonutils.NewBaseWidthParser[types.Event](columnsWidth, outputConfig),
	}
}

func NewExecParserWithK8sInfo(outputConfig *commonutils.OutputConfig) TraceParser[types.Event] {
	return newExecParser(outputConfig, commonutils.GetKubernetesColumns())
}

func NewExecParserWithRuntimeInfo(outputConfig *commonutils.OutputConfig) TraceParser[types.Event] {
	return newExecParser(outputConfig, commonutils.GetContainerRuntimeColumns())
}

func NewExecParser(outputConfig *commonutils.OutputConfig) TraceParser[types.Event] {
	return newExecParser(outputConfig, nil)
}

func (p *ExecParser) TransformEvent(event *types.Event) string {
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
			case "pid":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], event.Pid))
			case "ppid":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], event.Ppid))
			case "pcomm":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.Comm))
			case "ret":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], event.Retval))
			case "args":
				for _, arg := range event.Args {
					sb.WriteString(fmt.Sprintf("%s ", arg))
				}
			default:
				continue
			}

			// Needed when field is larger than the predefined columnsWidth.
			sb.WriteRune(' ')
		}

		return sb.String()
	})
}

func GetExecDefaultColumns() []string {
	// The columns that will be used in case the user does not specify which
	// specific columns they want to print through OutputConfig.
	return []string{
		"pid",
		"ppid",
		"pcomm",
		"ret",
		"args",
	}
}
