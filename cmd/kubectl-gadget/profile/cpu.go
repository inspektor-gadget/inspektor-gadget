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

package profile

import (
	"github.com/spf13/cobra"

	commonprofile "github.com/inspektor-gadget/inspektor-gadget/cmd/common/profile"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/cpu/types"
)

func newCPUCmd() *cobra.Command {
	var commonFlags utils.CommonFlags
	var cpuFlags commonprofile.CPUFlags

	runCmd := func(cmd *cobra.Command, args []string) error {
		if cpuFlags.ProfileUserOnly && cpuFlags.ProfileKernelOnly {
			return commonutils.WrapInErrArgsNotSupported("-U and -K can't be used at the same time")
		}

		parser, err := commonutils.NewGadgetParserWithK8sInfo(&commonFlags.OutputConfig, types.GetColumns())
		if err != nil {
			return commonutils.WrapInErrParserCreate(err)
		}

		params := map[string]string{}
		if cpuFlags.ProfileUserOnly {
			params[types.ProfileUserParam] = ""
		}
		if cpuFlags.ProfileKernelOnly {
			params[types.ProfileKernelParam] = ""
		}

		cpuGadget := &ProfileGadget{
			gadgetName:    "profile",
			params:        params,
			commonFlags:   &commonFlags,
			inProgressMsg: "Capturing stack traces",
			parser: &commonprofile.CPUParser{
				GadgetParser: *parser,
				OutputConfig: commonFlags.OutputConfig,
				CPUFlags:     &cpuFlags,
			},
		}

		return cpuGadget.Run()
	}

	cmd := commonprofile.NewCPUCmd(runCmd, &cpuFlags)

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}
