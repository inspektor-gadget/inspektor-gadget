// Copyright 2019-2023 The Inspektor Gadget authors
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
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/advise"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/environment"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"

	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/all-gadgets"
	// The script is not included in the all gadgets package.
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/script"
)

// common params for all gadgets
var params utils.CommonFlags

var rootCmd = &cobra.Command{
	Use:   "kubectl-gadget",
	Short: "Collection of gadgets for Kubernetes developers",
}

var catalogSkipCommands = []string{"deploy", "undeploy", "version"}

func init() {
	utils.FlagInit(rootCmd)
}

func main() {
	// grpcruntime.New() will try to fetch a catalog from the cluster by
	// default. Make sure we don't do this when certain commands are run
	// (as they just don't need it or imply that there are no nodes to
	// contact, yet).
	skipCatalog := false
	for _, arg := range os.Args[1:] {
		for _, skipCmd := range catalogSkipCommands {
			if strings.ToLower(arg) == skipCmd {
				skipCatalog = true
			}
		}
	}

	runtime := grpcruntime.New(skipCatalog)

	namespace, _ := utils.GetNamespace()
	runtime.SetDefaultValue(gadgets.K8SNamespace, namespace)

	// columnFilters for kubectl-gadget
	columnFilters := []columns.ColumnFilter{columns.WithoutExceptTag("runtime", "kubernetes")}
	common.AddCommandsFromRegistry(rootCmd, runtime, columnFilters)

	// Advise category is still being handled by CRs for now
	rootCmd.AddCommand(advise.NewAdviseCmd())

	rootCmd.AddCommand(&cobra.Command{
		Use:   "update-catalog",
		Short: "Download a new gadget catalog from the nodes to have it in sync with this client",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runtime.UpdateCatalog()
		},
	})

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	environment.Environment = environment.Kubernetes
}
