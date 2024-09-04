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
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/docker/go-units"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/formatter/textcolumns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
)

func NewListCmd() *cobra.Command {
	var noTrunc bool
	var outputMode string

	outputModes := []string{utils.OutputModeColumns, utils.OutputModeJSON, utils.OutputModeJSONPretty}

	cmd := &cobra.Command{
		Use:          "list",
		Short:        "List gadget images on the host",
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			images, err := oci.GetGadgetImages(context.TODO())
			if err != nil {
				return fmt.Errorf("list gadgets: %w", err)
			}

			switch outputMode {
			case utils.OutputModeJSON:
				bytes, err := json.Marshal(images)
				if err != nil {
					return fmt.Errorf("marshalling images to JSON: %w", err)
				}
				fmt.Fprint(cmd.OutOrStdout(), string(bytes))
			case utils.OutputModeJSONPretty:
				bytes, err := json.MarshalIndent(images, "", "  ")
				if err != nil {
					return fmt.Errorf("marshalling images to JSON: %w", err)
				}
				fmt.Fprint(cmd.OutOrStdout(), string(bytes))
			case utils.OutputModeColumns:
				isTerm := term.IsTerminal(int(os.Stdout.Fd()))

				cols := columns.MustCreateColumns[oci.GadgetImageDesc]()
				if !noTrunc && isTerm {
					cols.MustSetExtractor("digest", func(i *oci.GadgetImageDesc) any {
						if i.Digest == "" {
							return ""
						}
						// Return the shortened digest and remove the sha256: prefix
						return strings.TrimPrefix(i.Digest, "sha256:")[:12]
					})
					now := time.Now()
					cols.MustSetExtractor("created", func(i *oci.GadgetImageDesc) any {
						if t, err := time.Parse(time.RFC3339, i.Created); err == nil {
							return fmt.Sprintf("%s ago", strings.ToLower(units.HumanDuration(now.Sub(t))))
						}
						return ""
					})
				}

				formatter := textcolumns.NewFormatter(cols.GetColumnMap(), textcolumns.WithShouldTruncate(!noTrunc && isTerm))
				formatter.WriteTable(cmd.OutOrStdout(), images)
			default:
				return fmt.Errorf("invalid output mode %q, valid values are: %s", outputMode, strings.Join(outputModes, ", "))
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&noTrunc, "no-trunc", false, "Don't truncate output, this option is only valid when used in a terminal")
	cmd.Flags().StringVarP(
		&outputMode,
		"output",
		"o",
		utils.OutputModeColumns,
		fmt.Sprintf("Output mode, possible values are, %s", strings.Join(outputModes, ", ")),
	)

	return cmd
}
