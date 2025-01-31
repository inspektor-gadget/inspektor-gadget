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
	"runtime"
	"strings"

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
    Major         string `json:"major"`
    Minor         string `json:"minor"`
    GitVersion    string `json:"gitVersion"`
    GoVersion     string `json:"goVersion"`
    Compiler      string `json:"compiler"`
    Platform      string `json:"platform"`
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
		major, minor := version.GetMajorMinorVersion()
        versionDetails := version.GetVersionDetails()

		versionInfo := &VersionInfo{
            ClientVersion: &Version{
                Major:      major,
                Minor:      minor,
                GitVersion: fmt.Sprintf("v%s", strings.TrimPrefix(versionDetails["gitVersion"], "v")),
                GoVersion:  versionDetails["goVersion"],
                Compiler:   versionDetails["compiler"],
                Platform:   versionDetails["platform"],
            },
        }

		// Get server version information
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
				serverVersionStr := strings.TrimPrefix(info.ServerVersion, "v")
                versionParts := strings.Split(serverVersionStr, ".")
                serverMajor := "0"
                serverMinor := "0"
                if len(versionParts) >= 2 {
                    serverMajor = versionParts[0]
                    serverMinor = versionParts[1]
                }

                versionInfo.ServerVersion = &Version{
                    Major:      serverMajor,
                    Minor:      serverMinor,
                    GitVersion: fmt.Sprintf("v%s", serverVersionStr),
                    GoVersion:  runtime.Version(),
                    Compiler:   runtime.Compiler,
                    Platform:   fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
                }
			}
		} else if len(gadgetNamespaces) > 1 {
			fmt.Fprintf(os.Stderr, "Error: multiple Inspektor Gadget instances found in namespaces: %s\n", gadgetNamespaces)
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
			fmt.Printf("Client version: %s\n", versionInfo.ClientVersion.GitVersion)
			if versionInfo.ServerVersion != nil && versionInfo.ServerVersion.GitVersion != "" {
				fmt.Printf("Server version: %s\n", versionInfo.ServerVersion.GitVersion)
			} else {
				fmt.Println("Server version: not available")
			}
		default:
			return fmt.Errorf("invalid output format: %s", outputFormat)
		}

		return nil
	},
}
