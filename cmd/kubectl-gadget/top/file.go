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
	"strconv"

	"github.com/spf13/cobra"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/file/types"
)

func newFileCmd() *cobra.Command {
	var commonTopFlags CommonTopFlags

	var allFiles bool
	cols := types.GetColumns()

	cmd := &cobra.Command{
		Use:   fmt.Sprintf("file [interval=%d]", top.IntervalDefault),
		Short: "Periodically report read/write activity by file",
		RunE: func(cmd *cobra.Command, args []string) error {
			parser, err := commonutils.NewGadgetParserWithK8sInfo(&commonTopFlags.OutputConfig, types.GetColumns())
			if err != nil {
				return commonutils.WrapInErrParserCreate(err)
			}

			gadget := &TopGadget[types.Stats]{
				name:           "filetop",
				commonTopFlags: &commonTopFlags,
				params: map[string]string{
					types.AllFilesParam: strconv.FormatBool(allFiles),
				},
				parser:    parser,
				nodeStats: make(map[string][]*types.Stats),
				colMap:    cols.GetColumnMap(),
			}

			return gadget.Run(args)
		},
		SilenceUsage: true,
		Args:         cobra.MaximumNArgs(1),
	}

	addCommonTopFlags(cmd, &commonTopFlags, &commonTopFlags.CommonFlags, cols.ColumnMap, types.SortByDefault)

	cmd.Flags().BoolVarP(&allFiles, "all-files", "a", types.AllFilesDefault, "Include non-regular file types (sockets, FIFOs, etc)")

	return cmd
}
