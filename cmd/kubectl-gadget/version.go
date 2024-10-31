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

	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/internal/version"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
)

// VersionInfo represents the structure for version information output
type VersionInfo struct {
	ClientVersion *Version `json:"clientVersion,omitempty"`
	ServerVersion *Version `json:"serverVersion,omitempty"`
}

// Version contains detailed version information
type Version struct {
	Version string `json:"version"`
}

var outputFormat string

func init() {
	versionCmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Output format. One of: json|''")
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:          "version",
	Short:        "Show version",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Initialize version info structure
		versionInfo := &VersionInfo{
			ClientVersion: &Version{
				Version: version.Version().String(),
			},
		}

		// Get server version information
		gadgetNamespaces, err := utils.GetRunningGadgetNamespaces()
		if err != nil {
			return fmt.Errorf("getting running Inspektor Gadget instances: %w", err)
		}

		if len(gadgetNamespaces) == 1 {
			// Exactly one running gadget instance found, use it
			runtimeGlobalParams.Set(grpcruntime.ParamGadgetNamespace, gadgetNamespaces[0])
			info, err := grpcRuntime.InitDeployInfo()
			if err != nil {
				return fmt.Errorf("loading deploy info: %w", err)
			}
			versionInfo.ServerVersion = &Version{
				Version: info.ServerVersion,
			}
		} else if len(gadgetNamespaces) > 1 {
			return fmt.Errorf("multiple Inspektor Gadget instances found in namespaces: %v", gadgetNamespaces)
		}

		// Output based on format
		switch outputFormat {
		case "json":
			output, err := json.MarshalIndent(versionInfo, "", "  ")
			if err != nil {
				return fmt.Errorf("marshaling version info: %w", err)
			}
			fmt.Println(string(output))
		case "":
			fmt.Printf("Client version: v%s\n", versionInfo.ClientVersion.Version)
			if versionInfo.ServerVersion != nil && versionInfo.ServerVersion.Version != "" {
				fmt.Printf("Server version: v%s\n", versionInfo.ServerVersion.Version)
			} else {
				fmt.Println("Server version: not available")
			}
		default:
			return fmt.Errorf("invalid output format: %s", outputFormat)
		}

		return nil
	},
}
