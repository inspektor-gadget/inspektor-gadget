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
)

func newBlockIOCmd() *cobra.Command {
	var commonFlags utils.CommonFlags

	runCmd := func(cmd *cobra.Command, args []string) error {
		// Biolatency does not support filtering so we need to avoid adding
		// the default namespace configured in the kubeconfig file.
		if commonFlags.Namespace != "" && !commonFlags.NamespaceOverridden {
			commonFlags.Namespace = ""
		}

		if commonFlags.Node == "" {
			return commonutils.WrapInErrMissingArgs("--node")
		}

		blockIOGadget := &ProfileGadget{
			gadgetName:    "biolatency",
			commonFlags:   &commonFlags,
			inProgressMsg: "Tracing block device I/O",
			parser: &commonprofile.BlockIOParser{
				OutputConfig: commonFlags.OutputConfig,
			},
		}

		return blockIOGadget.Run()
	}

	cmd := commonprofile.NewBlockIOCmd(runCmd)

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}
