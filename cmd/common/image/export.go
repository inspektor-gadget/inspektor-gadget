// Copyright 2024 The Inspektor Gadget authors
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

func NewExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "export SRC_IMAGE [SRC_IMAGE n] DST_FILE",
		Short:        "Export the SRC_IMAGE images to DST_FILE",
		SilenceUsage: true,
		Args:         cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			l := len(args)
			srcImages := args[:l-1]
			dstFile := args[l-1]
			err := oci.ExportGadgetImages(context.TODO(), dstFile, srcImages...)
			if err != nil {
				return fmt.Errorf("exporting images: %w", err)
			}
			cmd.Printf("Successfully exported images to %s\n", dstFile)
			return nil
		},
	}

	return cmd
}
