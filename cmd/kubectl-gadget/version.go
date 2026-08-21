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
	"strconv"

	"github.com/blang/semver"
	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/internal/version"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
)

// VersionInfo represents the structure for version information output
type VersionInfo struct {
	ClientVersion *Version `json:"clientVersion,omitempty"`
	ServerVersion *Version `json:"serverVersion,omitempty"`

	// ServerPidNamespace is only reported with --details.
	ServerPidNamespace *PidNamespaceInfo `json:"serverPidNamespace,omitempty"`
}

// Version contains detailed version information
type Version struct {
	Version string `json:"version"`
}

// PidNamespaceInfo describes the PID namespace of the gadget service. The
// fields are pointers to distinguish "false" from "could not be determined".
type PidNamespaceInfo struct {
	IsHost *bool `json:"isHost,omitempty"`
	IsInit *bool `json:"isInit,omitempty"`
}

var (
	outputFormat string
	showDetails  bool
)

func init() {
	versionCmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Output format. One of: json|''")
	versionCmd.Flags().BoolVar(&showDetails, "details", false,
		"Show details about the gadget service, such as the PID namespace it runs in")
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

		info, err := getDeployedInfo()
		if err != nil {
			return fmt.Errorf("getting deployed version: %w", err)
		}

		if info != nil && info.ServerVersion != "" {
			serverVersion, err := semver.ParseTolerant(info.ServerVersion)
			if err != nil {
				return fmt.Errorf("parsing server version %q: %w", info.ServerVersion, err)
			}
			versionInfo.ServerVersion = &Version{
				Version: serverVersion.String(),
			}
		}

		if showDetails && info != nil {
			versionInfo.ServerPidNamespace = &PidNamespaceInfo{
				IsHost: info.ServerIsHostPidNs,
				IsInit: info.ServerIsInitPidNs,
			}
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
			if showDetails {
				printPidNamespaceInfo(versionInfo.ServerPidNamespace)
			}
		default:
			return fmt.Errorf("invalid output format: %s", outputFormat)
		}

		return nil
	},
}

func printPidNamespaceInfo(ns *PidNamespaceInfo) {
	if ns == nil {
		fmt.Println("Server PID namespace: not available")
		return
	}
	fmt.Printf("Server PID namespace: host: %s, init: %s\n",
		formatOptionalBool(ns.IsHost), formatOptionalBool(ns.IsInit))
}

// formatOptionalBool renders a tri-state: a value that could not be determined
// must not be shown as "false".
func formatOptionalBool(value *bool) string {
	if value == nil {
		return "unknown"
	}
	return strconv.FormatBool(*value)
}

// getDeployedInfo returns the information reported by the deployed Inspektor
// Gadget instance, or nil if there is none. Note that it only queries a single
// arbitrary node.
func getDeployedInfo() (*grpcruntime.Info, error) {
	gadgetNamespaces, err := utils.GetRunningGadgetNamespaces()
	if err != nil {
		return nil, fmt.Errorf("getting running gadget namespaces: %w", err)
	}

	switch len(gadgetNamespaces) {
	case 0:
		return nil, nil
	case 1:
		// Exactly one running gadget instance found, use it
		runtimeGlobalParams.Set(grpcruntime.ParamGadgetNamespace, gadgetNamespaces[0])
	default:
		return nil, fmt.Errorf("multiple Inspektor Gadget instances found in namespaces: %s", gadgetNamespaces)
	}

	info, err := grpcRuntime.GetInfo()
	if err != nil {
		return nil, fmt.Errorf("getting remote info: %w", err)
	}
	return info, nil
}

// GetDeployedVersion attempts to determine the version of the deployed Inspektor Gadget instance
func GetDeployedVersion() (semver.Version, error) {
	info, err := getDeployedInfo()
	if err != nil {
		return semver.Version{}, err
	}
	if info == nil || info.ServerVersion == "" {
		return semver.Version{}, nil
	}

	version, err := semver.ParseTolerant(info.ServerVersion)
	if err != nil {
		return semver.Version{}, fmt.Errorf("parsing server version %q: %w", info.ServerVersion, err)
	}
	return version, nil
}
