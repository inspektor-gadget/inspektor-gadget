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
	"github.com/spf13/cobra"

	commontrace "github.com/inspektor-gadget/inspektor-gadget/cmd/common/trace"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	byobTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/byob/types"
)

func newByobCmd() *cobra.Command {
	var commonFlags utils.CommonFlags
	var flags commontrace.ByobFlags

	runCmd := func(cmd *cobra.Command, args []string) error {
		parser, err := commonutils.NewGadgetParserWithK8sInfo(&commonFlags.OutputConfig, byobTypes.GetColumns())
		if err != nil {
			return commonutils.WrapInErrParserCreate(err)
		}

		progContent := ""
		if flags.File != "" {
			var err error
			progContent, err = commontrace.LoadByobFile(flags.File)
			if err != nil {
				return commonutils.WrapInErrInvalidArg("file", err)
			}
		}

		byobGadget := &TraceGadget[byobTypes.Event]{
			name:        "byob",
			commonFlags: &commonFlags,
			parser:      parser,
			params: map[string]string{
				"ociImage":    flags.OCIImage,
				"progContent": progContent,
			},
		}

		return byobGadget.Run()
	}

	cmd := commontrace.NewByobCmd(runCmd, &flags)

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}
