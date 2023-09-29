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
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
)

func NewPullCmd() *cobra.Command {
	var authOpts oci.AuthOptions
	cmd := &cobra.Command{
		Use:          "pull IMAGE",
		Short:        "Pull the specified image from a remote registry",
		SilenceUsage: true,
		Args:         cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			image := args[0]

			fmt.Printf("Pulling %s...\n", image)
			desc, err := oci.PullGadgetImage(context.TODO(), image, &authOpts)
			if err != nil {
				return fmt.Errorf("pulling gadget: %w", err)
			}
			fmt.Printf("Successfully pulled %s\n", desc.String())
			return nil
		},
	}
	utils.AddRegistryAuthVariablesAndFlags(cmd, &authOpts)
	return cmd
}
