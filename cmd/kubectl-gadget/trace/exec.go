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

package trace

import (
	commontrace "github.com/kinvolk/inspektor-gadget/cmd/common/trace"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/exec/types"

	"github.com/spf13/cobra"
)

func newExecCmd() *cobra.Command {
	var commonFlags utils.CommonFlags

	runCmd := func(cmd *cobra.Command, args []string) error {
		execGadget := &TraceGadget[types.Event]{
			name:        "execsnoop",
			commonFlags: &commonFlags,
			parser:      commontrace.NewExecParserWithK8sInfo(&commonFlags.OutputConfig),
		}

		return execGadget.Run()
	}

	cmd := commontrace.NewExecCmd(runCmd)

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}
