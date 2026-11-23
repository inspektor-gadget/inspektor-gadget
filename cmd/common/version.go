// Copyright 2023-2026 The Inspektor Gadget authors
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

package common

import (
	"encoding/json"
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/internal/version"
)

// VersionInfo is the structure used for the JSON output of the version
// command. It matches the output of kubectl-gadget so all the clients can be
// parsed the same way.
type VersionInfo struct {
	ClientVersion *Version `json:"clientVersion,omitempty"`
}

// Version contains detailed version information
type Version struct {
	Version string `json:"version"`
}

func NewVersionCmd() *cobra.Command {
	var outputFormat string

	cmd := &cobra.Command{
		Use:          "version",
		Short:        "Show version",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			switch outputFormat {
			case "json":
				versionInfo := &VersionInfo{
					ClientVersion: &Version{
						Version: version.Version().String(),
					},
				}
				output, err := json.MarshalIndent(versionInfo, "", "  ")
				if err != nil {
					return fmt.Errorf("marshaling version info: %w", err)
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(output))
			case "":
				fmt.Fprintf(cmd.OutOrStdout(), "v%s\n", version.Version().String())
			default:
				return fmt.Errorf("invalid output format: %s", outputFormat)
			}
			log.Debugf("Inspektor Gadget User Agent: %s\n", version.UserAgent())
			return nil
		},
	}

	cmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Output format. One of: json|''")

	return cmd
}
