// Copyright 2019-2021 The Inspektor Gadget authors
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
	"strconv"

	"github.com/spf13/cobra"

	commontop "github.com/inspektor-gadget/inspektor-gadget/cmd/common/top"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/tcp/types"
)

func newTCPCmd() *cobra.Command {
	var commonFlags utils.CommonFlags
	var flags commontop.TCPFlags

	cols := types.GetColumns()

	cmd := commontop.NewTCPCmd(func(cmd *cobra.Command, args []string) error {
		parser, err := commonutils.NewGadgetParserWithK8sInfo(&commonFlags.OutputConfig, cols)
		if err != nil {
			return commonutils.WrapInErrParserCreate(err)
		}

		parameters := make(map[string]string)
		if flags.Family != 0 {
			parameters[types.FamilyParam] = strconv.FormatUint(uint64(flags.Family), 10)
		}
		if flags.FilteredPid != 0 {
			parameters[types.PidParam] = strconv.FormatUint(uint64(flags.FilteredPid), 10)
		}

		gadget := &TopGadget[types.Stats]{
			TopGadget: commontop.TopGadget[types.Stats]{
				CommonTopFlags: &flags.CommonTopFlags,
				OutputConfig:   &commonFlags.OutputConfig,
				Parser:         parser,
				ColMap:         cols.ColumnMap,
			},
			name:        "tcptop",
			params:      parameters,
			commonFlags: &commonFlags,
			nodeStats:   make(map[string][]*types.Stats),
		}

		return gadget.Run(args)
	}, &flags)
	cmd.SilenceUsage = true

	commontop.AddCommonTopFlags(cmd, &flags.CommonTopFlags, cols.ColumnMap, types.SortByDefault)
	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}
