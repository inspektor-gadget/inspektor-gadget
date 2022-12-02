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

	"github.com/spf13/cobra"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/block-io/types"
)

func newBlockIOCmd() *cobra.Command {
	var commonTopFlags CommonTopFlags

	cols := types.GetColumns()

	cmd := &cobra.Command{
		Use:   fmt.Sprintf("block-io [interval=%d]", top.IntervalDefault),
		Short: "Periodically report block device I/O activity",
		RunE: func(cmd *cobra.Command, args []string) error {
			parser, err := commonutils.NewGadgetParserWithK8sInfo(&commonTopFlags.OutputConfig, types.GetColumns())
			if err != nil {
				return commonutils.WrapInErrParserCreate(err)
			}

			gadget := &TopGadget[types.Stats]{
				name:           "biotop",
				commonTopFlags: &commonTopFlags,
				parser:         parser,
				nodeStats:      make(map[string][]*types.Stats),
				colMap:         cols.GetColumnMap(),
			}

			return gadget.Run(args)
		},
		Args: cobra.MaximumNArgs(1),
	}

	addCommonTopFlags(cmd, &commonTopFlags, &commonTopFlags.CommonFlags, cols.ColumnMap, types.SortByDefault)

	return cmd
}
