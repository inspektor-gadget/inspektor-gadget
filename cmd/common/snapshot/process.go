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
	"sort"

	"github.com/spf13/cobra"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/process/types"
)

type ProcessFlags struct {
	showThreads bool
}

type ProcessParser struct {
	commonutils.GadgetParser[types.Event]

	flags *ProcessFlags
}

func newProcessParser(outputConfig *commonutils.OutputConfig, flags *ProcessFlags, cols *columns.Columns[types.Event], options ...commonutils.Option) (SnapshotParser[types.Event], error) {
	gadgetParser, err := commonutils.NewGadgetParser(outputConfig, cols, options...)
	if err != nil {
		return nil, commonutils.WrapInErrParserCreate(err)
	}

	return &ProcessParser{
		flags:        flags,
		GadgetParser: *gadgetParser,
	}, nil
}

func NewProcessParserWithK8sInfo(outputConfig *commonutils.OutputConfig, flags *ProcessFlags) (SnapshotParser[types.Event], error) {
	return newProcessParser(outputConfig, flags, types.GetColumns(), commonutils.WithMetadataTag(commonutils.KubernetesTag))
}

func NewProcessParserWithRuntimeInfo(outputConfig *commonutils.OutputConfig, flags *ProcessFlags) (SnapshotParser[types.Event], error) {
	return newProcessParser(outputConfig, flags, types.GetColumns(), commonutils.WithMetadataTag(commonutils.ContainerRuntimeTag))
}

func (p *ProcessParser) TransformToColumns(e *types.Event) string {
	return p.GadgetParser.TransformIntoColumns(e)
}

func (p *ProcessParser) GetOutputConfig() *commonutils.OutputConfig {
	return &commonutils.OutputConfig{
		OutputMode: commonutils.OutputModeColumns,
	}
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
