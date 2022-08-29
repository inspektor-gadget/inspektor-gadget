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
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/bind/types"
)

type BindParser struct {
	commonutils.BaseParser[types.Event]
}

func newBindParser(outputConfig *commonutils.OutputConfig, prependColumns []string) TraceParser[types.Event] {
	columnsWidth := map[string]int{
		// TODO: Move Kubernetes metadata columns to common/utils.
		"node":      -16,
		"namespace": -16,
		"pod":       -30,
		"container": -16,
		"pid":       -7,
		"comm":      -16,
		"proto":     -6,
		"addr":      -16,
		"port":      -7,
		"opts":      -7,
		"if":        -7,
	}

	if len(outputConfig.CustomColumns) == 0 {
		outputConfig.CustomColumns = GetBindDefaultColumns()
		if len(prependColumns) != 0 {
			outputConfig.CustomColumns = append(prependColumns, outputConfig.CustomColumns...)
		}
	}

	return &BindParser{
		BaseParser: commonutils.NewBaseWidthParser[types.Event](columnsWidth, outputConfig),
	}
}

func NewBindParserWithK8sInfo(outputConfig *commonutils.OutputConfig) TraceParser[types.Event] {
	return newBindParser(outputConfig, commonutils.GetKubernetesColumns())
}

func NewBindParserWithRuntimeInfo(outputConfig *commonutils.OutputConfig) TraceParser[types.Event] {
	return newBindParser(outputConfig, commonutils.GetContainerRuntimeColumns())
}

func NewBindParser(outputConfig *commonutils.OutputConfig) TraceParser[types.Event] {
	return newBindParser(outputConfig, nil)
}

func (p *BindParser) TransformEvent(event *types.Event) string {
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
			case "comm":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.Comm))
			case "proto":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.Protocol))
			case "addr":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.Addr))
			case "port":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], event.Port))
			case "opts":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.Options))
			case "if":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.Interface))
			default:
				continue
			}

			// Needed when field is larger than the predefined columnsWidth.
			sb.WriteRune(' ')
		}

		return sb.String()
	})
}

func GetBindDefaultColumns() []string {
	// The columns that will be used in case the user does not specify which
	// specific columns they want to print through OutputConfig.
	return []string{
		"pid",
		"comm",
		"proto",
		"addr",
		"port",
		"opts",
		"if",
	}
}
