// Copyright 2023 The Inspektor Gadget authors
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

package image

import (
	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

func NewImageCmd(r runtime.Runtime, addCommands []*cobra.Command) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "image",
		Short: "Manage gadget images",
	}

	// add only specific subcommands (only grpc-supported commands in case of gadgetctl/kubectl-gadget)
	if addCommands != nil {
		for _, c := range addCommands {
			cmd.AddCommand(c)
		}
		return cmd
	}

	// add all subcommands if not specified (in case of ig)
	cmd.AddCommand(NewBuildCmd())
	cmd.AddCommand(NewExportCmd())
	cmd.AddCommand(NewImportCmd())
	cmd.AddCommand(NewPushCmd())
	cmd.AddCommand(NewPullCmd())
	cmd.AddCommand(NewTagCmd())
	cmd.AddCommand(NewListCmd())
	cmd.AddCommand(NewInspectCmd(r))
	cmd.AddCommand(NewRemoveCmd())

	return cmd
}
