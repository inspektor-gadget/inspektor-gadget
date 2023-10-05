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
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/formatter/textcolumns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
)

func NewListCmd() *cobra.Command {
	var noTrunc bool
	cmd := &cobra.Command{
		Use:          "list",
		Short:        "List gadget images on the host",
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			images, err := oci.ListGadgetImages(context.TODO())
			if err != nil {
				return fmt.Errorf("list gadgets: %w", err)
			}

			cols := columns.MustCreateColumns[oci.GadgetImageDesc]()
			if !noTrunc {
				cols.MustSetExtractor("digest", func(i *oci.GadgetImageDesc) any {
					if i.Digest == "" {
						return ""
					}
					// Return the shortened digest and remove the sha256: prefix
					return strings.TrimPrefix(i.Digest, "sha256:")[:12]
				})
			}
			formatter := textcolumns.NewFormatter(cols.GetColumnMap())
			formatter.WriteTable(os.Stdout, images)
			return nil
		},
	}

	cmd.Flags().BoolVar(&noTrunc, "no-trunc", false, "Don't truncate output")

	return cmd
}
