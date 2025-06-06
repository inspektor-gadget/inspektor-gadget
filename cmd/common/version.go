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

package common

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/internal/version"
)

// VersionInfo contains client and server version information
type VersionInfo struct {
	ClientVersion *version.BuildInfo `json:"clientVersion,omitempty"`
	ServerVersion *version.BuildInfo `json:"serverVersion,omitempty"`
}

func NewVersionCmd() *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		RunE: func(cmd *cobra.Command, args []string) error {
			info := &VersionInfo{
				ClientVersion: version.GetBuildInfo(),
			}

			switch strings.ToLower(output) {
			case "json":
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(info)
			default:
				printVersionInfo(info)
			}

			log.Debugf("Inspektor Gadget User Agent: %s\n", version.UserAgent())
			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Output format. One of: json")

	return cmd
}

// printVersionInfo prints version information in a human-readable format
func printVersionInfo(info *VersionInfo) {
	cv := info.ClientVersion
	fmt.Printf("Client Version: %s\n", cv.Version)
	if cv.GitCommit != "" {
		fmt.Printf("Git Commit: %s\n", cv.GitCommit)
	}
	if cv.GitTreeState != "" {
		fmt.Printf("Git Tree State: %s\n", cv.GitTreeState)
	}
	if cv.BuildDate != "" {
		fmt.Printf("Build Date: %s\n", cv.BuildDate)
	}
	fmt.Printf("Go Version: %s\n", cv.GoVersion)
	fmt.Printf("Compiler: %s\n", cv.Compiler)
	fmt.Printf("Platform: %s\n", cv.Platform)

	if sv := info.ServerVersion; sv != nil {
		fmt.Println("\nServer Version:")
		fmt.Printf("  Version: %s\n", sv.Version)
		if sv.GitCommit != "" {
			fmt.Printf("  Git Commit: %s\n", sv.GitCommit)
		}
		if sv.GitTreeState != "" {
			fmt.Printf("  Git Tree State: %s\n", sv.GitTreeState)
		}
	}
}
