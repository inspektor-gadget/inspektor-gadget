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
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
)

func NewImportCmd() *cobra.Command {
	var outputMode string
	supportedOutputModes := []string{utils.OutputModeJSON, utils.OutputModeJSONPretty}

	cmd := &cobra.Command{
		Use:          "import SRC_FILE",
		Short:        "Import images from SRC_FILE",
		SilenceUsage: true,
		Args:         cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			srcFile := args[0]
			tags, err := oci.ImportGadgetImages(context.TODO(), srcFile)
			if err != nil {
				return fmt.Errorf("importing images: %w", err)
			}

			switch outputMode {
			case utils.OutputModeJSON:
				bytes, err := json.Marshal(tags)
				if err != nil {
					return fmt.Errorf("marshalling tags to JSON: %w", err)
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(bytes))
			case utils.OutputModeJSONPretty:
				bytes, err := json.MarshalIndent(tags, "", "  ")
				if err != nil {
					return fmt.Errorf("marshalling tags to JSON: %w", err)
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(bytes))
			case "":
				fmt.Fprintln(cmd.OutOrStdout(), "Successfully imported images:")
				for _, tag := range tags {
					fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", tag)
				}
			default:
				return fmt.Errorf("invalid output mode %q, valid values are: %s", outputMode, strings.Join(supportedOutputModes, ", "))
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(
		&outputMode,
		"output",
		"o",
		"",
		fmt.Sprintf("Output mode, possible values are: %s", strings.Join(supportedOutputModes, ", ")),
	)

	return cmd
}
