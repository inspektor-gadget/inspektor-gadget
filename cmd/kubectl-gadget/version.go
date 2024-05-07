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
	"fmt"

	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/internal/version"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:          "version",
	Short:        "Show version",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("Client version: v%s\n", version.Version())

		gadgetNamespaces, err := utils.GetRunningGadgetNamespaces()
		if err != nil {
			return fmt.Errorf("searching for running Inspektor Gadget instances: %w", err)
		}

		switch len(gadgetNamespaces) {
		case 0:
			fmt.Println("Server version:", "not installed")
			return nil
		case 1:
			// Exactly one running gadget instance found, use it
			runtimeGlobalParams.Set(grpcruntime.ParamGadgetNamespace, gadgetNamespaces[0])
		default:
			// Multiple running gadget instances found, error out
			return fmt.Errorf("multiple running Inspektor Gadget instances found in following namespaces: %v", gadgetNamespaces)
		}

		info, err := grpcRuntime.InitDeployInfo()
		if err != nil {
			return fmt.Errorf("loading deploy info: %w", err)
		}

		fmt.Printf("Server version: v%s\n", info.ServerVersion)

		return nil
	},
}
