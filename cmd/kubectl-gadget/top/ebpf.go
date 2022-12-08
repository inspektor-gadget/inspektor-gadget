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

package top

import (
	"fmt"

	commontop "github.com/inspektor-gadget/inspektor-gadget/cmd/common/top"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/types"

	"github.com/spf13/cobra"
)

type EbpfParser struct {
	commonutils.BaseParser[types.Stats]

	flags *commontop.CommonTopFlags
}

func newEbpfCmd() *cobra.Command {
	var commonFlags utils.CommonFlags
	var flags commontop.CommonTopFlags

	cols := types.GetColumns()

	cmd := commontop.NewEbpfCmd(func(cmd *cobra.Command, args []string) error {
		parser, err := commonutils.NewGadgetParserWithK8sInfo(&commonFlags.OutputConfig, cols)
		if err != nil {
			return commonutils.WrapInErrParserCreate(err)
		}

		gadget := &TopGadget[types.Stats]{
			TopGadget: commontop.TopGadget[types.Stats]{
				CommonTopFlags: &flags,
				OutputConfig:   &commonFlags.OutputConfig,
				Parser:         parser,
				ColMap:         cols.ColumnMap,
			},
			name:        "ebpftop",
			commonFlags: &commonFlags,
			nodeStats:   make(map[string][]*types.Stats),
		}

		if commonFlags.NamespaceOverridden {
			return commonutils.WrapInErrInvalidArg("--namespace / -n",
				fmt.Errorf("this gadget cannot filter by namespace"))
		}
		if commonFlags.Podname != "" {
			return commonutils.WrapInErrInvalidArg("--podname / -p",
				fmt.Errorf("this gadget cannot filter by pod name"))
		}
		if commonFlags.Containername != "" {
			return commonutils.WrapInErrInvalidArg("--containername / -c",
				fmt.Errorf("this gadget cannot filter by container name"))
		}
		if len(commonFlags.Labels) > 0 {
			return commonutils.WrapInErrInvalidArg("--selector / -l",
				fmt.Errorf("this gadget cannot filter by selector"))
		}

		return gadget.Run(args)
	})
	cmd.SilenceUsage = true

	commontop.AddCommonTopFlags(cmd, &flags, cols.ColumnMap, types.SortByDefault)
	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}
