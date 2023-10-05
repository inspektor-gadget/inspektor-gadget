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

	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
)

func NewTagCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "tag SRC_IMAGE DST_IMAGE",
		Short:        "Tag the local SRC_IMAGE image with the DST_IMAGE",
		SilenceUsage: true,
		Args:         cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			srcImage := args[0]
			dstImage := args[1]
			desc, err := oci.TagGadgetImage(context.TODO(), srcImage, dstImage)
			if err != nil {
				return fmt.Errorf("tagging image: %w", err)
			}

			fmt.Printf("Successfully tagged with %s\n", desc.String())
			return nil
		},
	}

	return cmd
}
