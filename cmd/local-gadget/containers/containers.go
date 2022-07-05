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

package containers

import (
	"fmt"

	"github.com/kinvolk/inspektor-gadget/cmd/local-gadget/utils"
	localgadgetmanager "github.com/kinvolk/inspektor-gadget/pkg/local-gadget-manager"
	"github.com/spf13/cobra"
)

func NewListContainersCmd() *cobra.Command {
	var commonFlags utils.CommonFlags

	cmd := &cobra.Command{
		Use:   "list-containers",
		Short: "List all containers",
		RunE: func(cmd *cobra.Command, args []string) error {
			localGadgetManager, err := localgadgetmanager.NewManager(commonFlags.RuntimeConfigs)
			if err != nil {
				return fmt.Errorf("failed to initialize manager: %w", err)
			}
			defer localGadgetManager.Close()

			for _, n := range localGadgetManager.ListContainers() {
				fmt.Println(n)
			}

			return nil
		},
	}

	utils.AddCommonFlags(cmd, &commonFlags)
	return cmd
}
