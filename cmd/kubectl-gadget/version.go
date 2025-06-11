// Copyright 2019-2021 The Inspektor Gadget authors
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

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/internal/version"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
)

// VersionInfo represents the structure for version information output
type VersionInfo struct {
	ClientVersion *version.BuildInfo `json:"clientVersion,omitempty"`
	ServerVersion *version.BuildInfo `json:"serverVersion,omitempty"`
}

var (
	outputFormat string
	versionCmd   = &cobra.Command{
		Use:          "version",
		Short:        "Show version information",
		SilenceUsage: true,
		RunE:         runVersion,
	}
)

func init() {
	versionCmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Output format. One of: json")
	rootCmd.AddCommand(versionCmd)
}

func runVersion(cmd *cobra.Command, args []string) error {
	// Initialize version info structure
	versionInfo := &VersionInfo{
		ClientVersion: version.GetBuildInfo(),
	}

	// Get server version information if available
	gadgetNamespaces, err := utils.GetRunningGadgetNamespaces()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: getting running Inspektor Gadget instances: %s\n", err)
	}

	if len(gadgetNamespaces) == 1 {
		// Exactly one running gadget instance found, use it
		runtimeGlobalParams.Set(grpcruntime.ParamGadgetNamespace, gadgetNamespaces[0])
		info, err := grpcRuntime.InitDeployInfo()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: loading deploy info: %s\n", err)
		} else {
			// Create a basic BuildInfo for the server with the version we know
			versionInfo.ServerVersion = &version.BuildInfo{
				Version: info.ServerVersion,
			}
		}
	} else if len(gadgetNamespaces) > 1 {
		fmt.Fprintf(os.Stderr, "Error: multiple Inspektor Gadget instances found in namespaces: %s\n", gadgetNamespaces)
	}

	// Output based on format
	switch strings.ToLower(outputFormat) {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(versionInfo)
	default:
		printVersionInfo(versionInfo)
	}

	return nil
}

// printVersionInfo prints version information in a human-readable format
func printVersionInfo(info *VersionInfo) {
	cv := info.ClientVersion
	fmt.Printf("Client Version: %s\n", cv.Version)
	if cv.Major != "" && cv.Minor != "" {
		fmt.Printf("  Major: %s\n", cv.Major)
		fmt.Printf("  Minor: %s\n", cv.Minor)
	}
	if cv.GitCommit != "" {
		fmt.Printf("  Git Commit: %s\n", cv.GitCommit)
	}
	if cv.GitTreeState != "" {
		fmt.Printf("  Git Tree State: %s\n", cv.GitTreeState)
	}
	if cv.BuildDate != "" {
		fmt.Printf("  Build Date: %s\n", cv.BuildDate)
	}
	fmt.Printf("  Go Version: %s\n", cv.GoVersion)
	fmt.Printf("  Compiler: %s\n", cv.Compiler)
	fmt.Printf("  Platform: %s\n", cv.Platform)

	if sv := info.ServerVersion; sv != nil {
		fmt.Println("\nServer Version:")
		fmt.Printf("  Version: %s\n", sv.Version)
		// Server might not have all the build info fields
		if sv.Major != "" && sv.Minor != "" {
			fmt.Printf("  Major: %s\n", sv.Major)
			fmt.Printf("  Minor: %s\n", sv.Minor)
		}
		if sv.GitCommit != "" {
			fmt.Printf("  Git Commit: %s\n", sv.GitCommit)
		}
		if sv.GitTreeState != "" {
			fmt.Printf("  Git Tree State: %s\n", sv.GitTreeState)
		}
	} else {
		fmt.Println("\nServer: not available")
	}
}
