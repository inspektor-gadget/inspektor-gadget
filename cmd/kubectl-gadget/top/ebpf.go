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

package top

import (
	"fmt"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/types"

	"github.com/spf13/cobra"
)

type EbpfParser struct {
	commonutils.BaseParser[types.Stats]

	flags *CommonTopFlags
}

func newEbpfCmd() *cobra.Command {
	var commonTopFlags CommonTopFlags

	cols := types.GetColumns()

	cmd := &cobra.Command{
		Use:   fmt.Sprintf("ebpf [interval=%d]", top.IntervalDefault),
		Short: "Periodically report ebpf runtime stats",
		RunE: func(cmd *cobra.Command, args []string) error {
			parser, err := commonutils.NewGadgetParserWithK8sInfo(&commonTopFlags.OutputConfig, types.GetColumns())
			if err != nil {
				return commonutils.WrapInErrParserCreate(err)
			}

			gadget := &TopGadget[types.Stats]{
				name:           "ebpftop",
				commonTopFlags: &commonTopFlags,
				parser:         parser,
				nodeStats:      make(map[string][]*types.Stats),
				colMap:         cols.GetColumnMap(),
			}

			if commonTopFlags.NamespaceOverridden {
				return commonutils.WrapInErrInvalidArg("--namespace / -n",
					fmt.Errorf("this gadget cannot filter by namespace"))
			}
			if commonTopFlags.Podname != "" {
				return commonutils.WrapInErrInvalidArg("--podname / -p",
					fmt.Errorf("this gadget cannot filter by pod name"))
			}
			if commonTopFlags.Containername != "" {
				return commonutils.WrapInErrInvalidArg("--containername / -c",
					fmt.Errorf("this gadget cannot filter by container name"))
			}
			if len(commonTopFlags.Labels) > 0 {
				return commonutils.WrapInErrInvalidArg("--selector / -l",
					fmt.Errorf("this gadget cannot filter by selector"))
			}

			return gadget.Run(args)
		},
		SilenceUsage: true,
		Args:         cobra.MaximumNArgs(1),
	}

	addCommonTopFlags(cmd, &commonTopFlags, &commonTopFlags.CommonFlags, cols.ColumnMap, types.SortByDefault)

	return cmd
}
