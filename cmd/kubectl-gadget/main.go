// Copyright 2019-2024 The Inspektor Gadget authors
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
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	// Import this early to set the enrivonment variable before any other package is imported
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/environment/k8s"
	paramsPkg "github.com/inspektor-gadget/inspektor-gadget/pkg/params"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
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
var (
	params              utils.CommonFlags
	runtimeGlobalParams *paramsPkg.Params
	grpcRuntime         *grpcruntime.Runtime
)

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
	isHelp := false
	isVersion := false
	isDeployUndeploy := false
	for _, arg := range os.Args[1:] {
		for _, skipCmd := range infoSkipCommands {
			if arg == skipCmd {
				skipInfo = true
			}
		}

		isVersion = isVersion || arg == "version"
		isDeployUndeploy = isDeployUndeploy || arg == "deploy" || arg == "undeploy"
		isHelp = isHelp || arg == "--help" || arg == "-h"
	}

	grpcRuntime = grpcruntime.New(grpcruntime.WithConnectUsingK8SProxy)
	runtimeGlobalParams = grpcRuntime.GlobalParamDescs().ToParams()
	common.AddFlags(rootCmd, runtimeGlobalParams, nil, grpcRuntime)
	grpcRuntime.Init(runtimeGlobalParams)
	config, err := utils.KubernetesConfigFlags.ToRESTConfig()
	if err != nil {
		log.Fatalf("Creating RESTConfig: %s", err)
	}
	grpcRuntime.SetRestConfig(config)

	// evaluate flags early for runtimeGlobalParams; this will make
	// sure that all flags relevant for the grpc connection are ready
	// to be used

	err = commonutils.ParseEarlyFlags(rootCmd, os.Args[1:])
	if err != nil {
		// Analogous to cobra error message
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if !isHelp && !isDeployUndeploy && !runtimeGlobalParams.Get(grpcruntime.ParamGadgetNamespace).IsSet() {
		gadgetNamespaces, err := utils.GetRunningGadgetNamespaces()
		if err != nil {
			log.Fatalf("Searching for running Inspektor Gadget instances: %s", err)
		}

		switch len(gadgetNamespaces) {
		case 0:
			if !isVersion {
				log.Fatalf("No running Inspektor Gadget instances found")
			}
		case 1:
			// Exactly one running gadget instance found, use it
			runtimeGlobalParams.Set(grpcruntime.ParamGadgetNamespace, gadgetNamespaces[0])
		default:
			// Multiple running gadget instances found, error out
			log.Fatalf("Multiple running Inspektor Gadget instances found in following namespaces: %v", gadgetNamespaces)
		}
	}

	if !skipInfo {
		grpcRuntime.InitDeployInfo()
	}

	namespace, _ := utils.GetNamespace()
	grpcRuntime.SetDefaultValue(gadgets.K8SNamespace, namespace)
	gadgetNamespace := runtimeGlobalParams.Get(grpcruntime.ParamGadgetNamespace).AsString()

	hiddenColumnTags := []string{"runtime"}
	common.AddCommandsFromRegistry(rootCmd, grpcRuntime, hiddenColumnTags)

	// Advise and traceloop category is still being handled by CRs for now
	rootCmd.AddCommand(advise.NewAdviseCmd(gadgetNamespace))
	rootCmd.AddCommand(NewTraceloopCmd(gadgetNamespace))
	rootCmd.AddCommand(common.NewSyncCommand(grpcRuntime))
	rootCmd.AddCommand(common.NewRunCommand(rootCmd, grpcRuntime, hiddenColumnTags))

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
