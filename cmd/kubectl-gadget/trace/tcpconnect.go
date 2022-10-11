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
	"github.com/spf13/cobra"

	commontrace "github.com/kinvolk/inspektor-gadget/cmd/common/trace"
	commonutils "github.com/kinvolk/inspektor-gadget/cmd/common/utils"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	tcpconnectTypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/tcpconnect/types"
)

func newTcpconnectCmd() *cobra.Command {
	var commonFlags utils.CommonFlags

	runCmd := func(*cobra.Command, []string) error {
		parser, err := commonutils.NewGadgetParserWithK8sInfo(
			&commonFlags.OutputConfig,
			tcpconnectTypes.GetColumns(),
		)
		if err != nil {
			return commonutils.WrapInErrParserCreate(err)
		}

		tcpconnectGadget := &TraceGadget[tcpconnectTypes.Event]{
			name:        "tcpconnect",
			commonFlags: &commonFlags,
			parser:      parser,
		}

		return tcpconnectGadget.Run()
	}

	cmd := commontrace.NewTcpconnectCmd(runCmd)

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}
