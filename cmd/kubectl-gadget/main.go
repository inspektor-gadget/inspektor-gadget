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

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	// Import this early to set the enrivonment variable before any other package is imported
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/environment/k8s"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/advise"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/experimental"

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

var infoSkipCommands = []string{"deploy", "undeploy", "version"}

func init() {
	utils.FlagInit(rootCmd)
}

func main() {
	if experimental.Enabled() {
		log.Info("Experimental features enabled")
	}

	common.AddVerboseFlag(rootCmd)

	// grpcruntime.New() will try to fetch the info from the cluster by
	// default. Make sure we don't do this when certain commands are run
	// (as they just don't need it or imply that there are no nodes to
	// contact, yet).
	skipInfo := false
	for _, arg := range os.Args[1:] {
		for _, skipCmd := range infoSkipCommands {
			if strings.ToLower(arg) == skipCmd {
				skipInfo = true
			}
		}
	}

	runtime := grpcruntime.New(skipInfo)

	namespace, _ := utils.GetNamespace()
	runtime.SetDefaultValue(gadgets.K8SNamespace, namespace)

	hiddenColumnTags := []string{"runtime"}
	common.AddCommandsFromRegistry(rootCmd, runtime, hiddenColumnTags)

	// Advise category is still being handled by CRs for now
	rootCmd.AddCommand(advise.NewAdviseCmd())

	rootCmd.AddCommand(&cobra.Command{
		Use:   "sync",
		Short: "Synchronize gadget information with your cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runtime.UpdateDeployInfo()
		},
	})

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
