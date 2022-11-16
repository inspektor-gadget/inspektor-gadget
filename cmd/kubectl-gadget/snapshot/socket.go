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

package snapshot

import (
	"github.com/spf13/cobra"

	commonsnapshot "github.com/inspektor-gadget/inspektor-gadget/cmd/common/snapshot"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/socket/types"
)

func newSocketCmd() *cobra.Command {
	var commonFlags utils.CommonFlags
	var flags commonsnapshot.SocketFlags

	runCmd := func(cmd *cobra.Command, args []string) error {
		parser, err := commonsnapshot.NewSocketParserWithK8sInfo(&commonFlags.OutputConfig, &flags)
		if err != nil {
			return commonutils.WrapInErrParserCreate(err)
		}

		socketGadget := &SnapshotGadget[types.Event]{
			name:        "socket-collector",
			commonFlags: &commonFlags,
			SnapshotGadgetPrinter: commonsnapshot.SnapshotGadgetPrinter[types.Event]{
				Parser: parser,
			},
			params: map[string]string{
				"protocol": flags.Protocol,
			},
		}

		return socketGadget.Run()
	}

	cmd := commonsnapshot.NewSocketCmd(runCmd, &flags)

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}
