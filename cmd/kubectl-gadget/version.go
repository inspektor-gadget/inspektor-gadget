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

	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/internal/version"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
	"github.com/spf13/cobra"
)

// VersionInfo represents the structure for version information output
type VersionInfo struct {
	ClientVersion *Version `json:"clientVersion,omitempty"`
	ServerVersion *Version `json:"serverVersion,omitempty"`
}

// Version contains detailed version information
type Version struct {
	Version string `json:"version"`
	Status  string `json:"status,omitempty"`
}

func init() {
	versionCmd.Flags().StringP("output", "o", "", "Output format. One of: json|''")
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:          "version",
	Short:        "Show version",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		outputFormat, err := cmd.Flags().GetString("output")
		if err != nil {
			return fmt.Errorf("error getting output format: %w", err)
		}

		// Initialize version info structure
		versionInfo := &VersionInfo{
			ClientVersion: &Version{
				Version: version.Version().String(),
			},
		}

		// Get server version information
		gadgetNamespaces, err := utils.GetRunningGadgetNamespaces()
		if err != nil {
			return fmt.Errorf("searching for running Inspektor Gadget instances: %w", err)
		}

		switch len(gadgetNamespaces) {
		case 0:
			versionInfo.ServerVersion = &Version{
				Status: "not installed",
			}
		case 1:
			// Exactly one running gadget instance found, use it
			runtimeGlobalParams.Set(grpcruntime.ParamGadgetNamespace, gadgetNamespaces[0])
			info, err := grpcRuntime.InitDeployInfo()
			if err != nil {
				return fmt.Errorf("loading deploy info: %w", err)
			}
			versionInfo.ServerVersion = &Version{
				Version: info.ServerVersion,
			}
		default:
			return fmt.Errorf("multiple running Inspektor Gadget instances found in following namespaces: %v", gadgetNamespaces)
		}

		// Output based on format
		switch outputFormat {
		case "json":
			return outputJSON(versionInfo)
		case "":
			return outputDefault(versionInfo)
		default:
			return fmt.Errorf("invalid output format: %s", outputFormat)
		}
	},
}

func outputJSON(info *VersionInfo) error {
	output, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling version info: %w", err)
	}
	fmt.Println(string(output))
	return nil
}

func outputDefault(info *VersionInfo) error {
	fmt.Printf("Client version: v%s\n", info.ClientVersion.Version)
	if info.ServerVersion.Status != "" {
		fmt.Printf("Server version: %s\n", info.ServerVersion.Status)
	} else {
		fmt.Printf("Server version: v%s\n", info.ServerVersion.Version)
	}
	return nil
}
