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

package snapshot

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	commonutils "github.com/kinvolk/inspektor-gadget/cmd/common/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/snapshot/process/types"
)

type ProcessFlags struct {
	showThreads bool
}

type ProcessParser struct {
	commonutils.BaseParser[types.Event]

	flags *ProcessFlags
}

func newProcessParser(outputConfig *commonutils.OutputConfig, flags *ProcessFlags, prependColumns []string) SnapshotParser[types.Event] {
	availableColumns := []string{
		// TODO: Move Kubernetes metadata columns to common/utils.
		"node",
		"namespace",
		"pod",
		"container",
		"comm",
		"tgid",
		"pid",
	}

	if len(outputConfig.CustomColumns) == 0 {
		outputConfig.CustomColumns = GetProcessDefaultColumns()
		if len(prependColumns) != 0 {
			outputConfig.CustomColumns = append(prependColumns, outputConfig.CustomColumns...)
		}
	}

	if outputConfig.OutputMode == commonutils.OutputModeColumns && flags.showThreads {
		for index, col := range outputConfig.CustomColumns {
			if col != "pid" {
				continue
			}

			outputConfig.CustomColumns = append(outputConfig.CustomColumns[:index],
				append([]string{"tgid"}, outputConfig.CustomColumns[index:]...)...)

			break
		}
	}

	return &ProcessParser{
		BaseParser: commonutils.NewBaseTabParser[types.Event](availableColumns, outputConfig),
		flags:      flags,
	}
}

func NewProcessParserWithK8sInfo(outputConfig *commonutils.OutputConfig, flags *ProcessFlags) SnapshotParser[types.Event] {
	return newProcessParser(outputConfig, flags, commonutils.GetKubernetesColumns())
}

func NewProcessParserWithRuntimeInfo(outputConfig *commonutils.OutputConfig, flags *ProcessFlags) SnapshotParser[types.Event] {
	return newProcessParser(outputConfig, flags, commonutils.GetContainerRuntimeColumns())
}

func NewProcessParser(outputConfig *commonutils.OutputConfig, flags *ProcessFlags) SnapshotParser[types.Event] {
	return newProcessParser(outputConfig, flags, nil)
}

func (p *ProcessParser) TransformToColumns(e *types.Event) string {
	var sb strings.Builder

	for _, col := range p.OutputConfig.CustomColumns {
		switch col {
		case "node":
			sb.WriteString(fmt.Sprintf("%s", e.KubernetesNode))
		case "namespace":
			sb.WriteString(fmt.Sprintf("%s", e.KubernetesNamespace))
		case "pod":
			sb.WriteString(fmt.Sprintf("%s", e.KubernetesPodName))
		case "container":
			sb.WriteString(fmt.Sprintf("%s", e.KubernetesContainerName))
		case "comm":
			sb.WriteString(fmt.Sprintf("%s", e.Command))
		case "tgid":
			sb.WriteString(fmt.Sprintf("%d", e.Tgid))
		case "pid":
			sb.WriteString(fmt.Sprintf("%d", e.Pid))
		default:
			continue
		}
		sb.WriteRune('\t')
	}

	return sb.String()
}

func (p *ProcessParser) SortEvents(allProcesses *[]types.Event) {
	if !p.flags.showThreads {
		allProcessesTrimmed := []types.Event{}
		for _, i := range *allProcesses {
			if i.Tgid == i.Pid {
				allProcessesTrimmed = append(allProcessesTrimmed, i)
			}
		}
		*allProcesses = allProcessesTrimmed
	}

	sort.Slice(*allProcesses, func(i, j int) bool {
		pi, pj := (*allProcesses)[i], (*allProcesses)[j]
		switch {
		case pi.KubernetesNode != pj.KubernetesNode:
			return pi.KubernetesNode < pj.KubernetesNode
		case pi.KubernetesNamespace != pj.KubernetesNamespace:
			return pi.KubernetesNamespace < pj.KubernetesNamespace
		case pi.KubernetesPodName != pj.KubernetesPodName:
			return pi.KubernetesPodName < pj.KubernetesPodName
		case pi.KubernetesContainerName != pj.KubernetesContainerName:
			return pi.KubernetesContainerName < pj.KubernetesContainerName
		case pi.Command != pj.Command:
			return pi.Command < pj.Command
		case pi.Tgid != pj.Tgid:
			return pi.Tgid < pj.Tgid
		default:
			return pi.Pid < pj.Pid
		}
	})
}

func GetProcessDefaultColumns() []string {
	// The columns that will be used in case the user does not specify which
	// specific columns they want to print through OutputConfig.
	return []string{
		"comm",
		"pid",
	}
}

func NewProcessCmd(runCmd func(*cobra.Command, []string) error, flags *ProcessFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "process",
		Short: "Gather information about running processes",
		RunE:  runCmd,
	}

	cmd.PersistentFlags().BoolVarP(
		&flags.showThreads,
		"threads",
		"t",
		false,
		"Show all threads",
	)

	return cmd
}
