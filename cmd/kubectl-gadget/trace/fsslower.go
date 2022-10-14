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
	"strconv"

	"github.com/spf13/cobra"

	commontrace "github.com/inspektor-gadget/inspektor-gadget/cmd/common/trace"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	fsslowerTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/fsslower/types"
)

func newFsSlowerCmd() *cobra.Command {
	var commonFlags utils.CommonFlags
	var flags commontrace.FsSlowerFlags

	runCmd := func(cmd *cobra.Command, args []string) error {
		parser, err := commonutils.NewGadgetParserWithK8sInfo(&commonFlags.OutputConfig, fsslowerTypes.GetColumns())
		if err != nil {
			return commonutils.WrapInErrParserCreate(err)
		}

		fsslowerGadget := &TraceGadget[fsslowerTypes.Event]{
			name:        "fsslower",
			commonFlags: &commonFlags,
			parser:      parser,
			params: map[string]string{
				"filesystem": flags.Filesystem,
				"minlatency": strconv.FormatUint(uint64(flags.MinLatency), 10),
			},
		}

		return fsslowerGadget.Run()
	}

	cmd := commontrace.NewFsSlowerCmd(runCmd, &flags)
	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}
