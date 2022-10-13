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

package audit

import (
	"fmt"
	"strings"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/audit/seccomp/types"
)

type SeccompParser struct {
	commonutils.BaseParser[types.Event]
}

// newSeccompParser returns a parser already configured to manage the output of
// the audit/seccomp gadget. Consider that outputConfig describes how to print
// the gadget's output and prependK8sMetadata indicates whether to prepend
// the Kubernetes metadata columns or not.
func newSeccompParser(outputConfig *commonutils.OutputConfig, prependK8sMetadata bool) *SeccompParser {
	columnsWidth := map[string]int{
		// TODO: Move Kubernetes metadata columns to common/utils.
		"node":      -16,
		"namespace": -16,
		"pod":       -30,
		"container": -16,
		"pid":       -7,
		"comm":      -16,
		"syscall":   -16,
		"code":      -16,
		"mntns":     -12,
	}

	if len(outputConfig.CustomColumns) == 0 {
		outputConfig.CustomColumns = GetSeccompDefaultColumns()
		if prependK8sMetadata {
			outputConfig.CustomColumns = append(commonutils.GetKubernetesColumns(), outputConfig.CustomColumns...)
		}
	}

	return &SeccompParser{
		BaseParser: commonutils.NewBaseWidthParser[types.Event](columnsWidth, outputConfig),
	}
}

func NewSeccompK8sParser(outputConfig *commonutils.OutputConfig) *SeccompParser {
	return newSeccompParser(outputConfig, true)
}

func NewSeccompParser(outputConfig *commonutils.OutputConfig) *SeccompParser {
	return newSeccompParser(outputConfig, false)
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
			case "mntns":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], e.MountNsID))
			default:
				continue
			}

			// Needed when field is larger than the predefined columnsWidth.
			sb.WriteRune(' ')
		}

		return sb.String()
	})
}

func GetSeccompDefaultColumns() []string {
	// The columns that will be used in case the user does not specify which
	// specific columns they want to print through OutputConfig.
	return []string{
		"pid",
		"comm",
		"syscall",
		"code",
	}
}
