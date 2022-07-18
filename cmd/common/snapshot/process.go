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

	commonutils "github.com/kinvolk/inspektor-gadget/cmd/common/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/process-collector/types"
	"github.com/spf13/cobra"
)

const (
	ProcessGadgetName = "process-collector"
)

type ProcessFlags struct {
	showThreads bool
}

type ProcessParser struct {
	commonutils.BaseParser

	processFlags *ProcessFlags
}

func NewCommonProcessCmd(
	processFlags *ProcessFlags,
	availableColumns []string,
	outputConfig *commonutils.OutputConfig,
	customRun func(callback func(traceOutputMode string, results []string) error) error,
) *cobra.Command {
	processGadget := &SnapshotGadget[types.Event]{
		parser: &ProcessParser{
			BaseParser:   commonutils.NewBaseTabParser(availableColumns, outputConfig),
			processFlags: processFlags,
		},
		customRun: customRun,
	}

	cmd := &cobra.Command{
		Use:   "process",
		Short: "Gather information about running processes",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if outputConfig.OutputMode == commonutils.OutputModeColumns && processFlags.showThreads {
				for index, col := range outputConfig.CustomColumns {
					if col != "pid" {
						continue
					}

					outputConfig.CustomColumns = append(outputConfig.CustomColumns[:index],
						append([]string{"tgid"}, outputConfig.CustomColumns[index:]...)...)

					break
				}
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return processGadget.Run()
		},
	}

	cmd.PersistentFlags().BoolVarP(
		&processFlags.showThreads,
		"threads",
		"t",
		false,
		"Show all threads",
	)

	return cmd
}

func (p *ProcessParser) TransformEvent(e *types.Event) string {
	var sb strings.Builder

	for _, col := range p.OutputConfig.CustomColumns {
		switch col {
		case "node":
			sb.WriteString(fmt.Sprintf("%s", e.Node))
		case "namespace":
			sb.WriteString(fmt.Sprintf("%s", e.Namespace))
		case "pod":
			sb.WriteString(fmt.Sprintf("%s", e.Pod))
		case "container":
			sb.WriteString(fmt.Sprintf("%s", e.Container))
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
	if !p.processFlags.showThreads {
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
		case pi.Node != pj.Node:
			return pi.Node < pj.Node
		case pi.Namespace != pj.Namespace:
			return pi.Namespace < pj.Namespace
		case pi.Pod != pj.Pod:
			return pi.Pod < pj.Pod
		case pi.Container != pj.Container:
			return pi.Container < pj.Container
		case pi.Command != pj.Command:
			return pi.Command < pj.Command
		case pi.Tgid != pj.Tgid:
			return pi.Tgid < pj.Tgid
		default:
			return pi.Pid < pj.Pid
		}
	})
}
