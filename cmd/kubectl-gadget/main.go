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
	img "github.com/inspektor-gadget/inspektor-gadget/cmd/common/image"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/advise"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	igconfig "github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/experimental"

	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/all-gadgets"
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

func init() {
	utils.FlagInit(rootCmd)
}

func main() {
	if experimental.Enabled() {
		log.Info("Experimental features enabled")
	}

	common.AddConfigFlag(rootCmd)
	common.AddVerboseFlag(rootCmd)

	// Some commands don't need the gadget namespace. Run then before to avoid
	// printing warnings about gadget namespace not found.
	needGadgetNamespace := true
	isHelp := len(os.Args) == 1

	// Need to loop through all arguments to skip flags...
	for _, arg := range os.Args[1:] {
		switch arg {
		case "completion", "deploy", "version":
			needGadgetNamespace = false
		case "--help", "-h", "help":
			isHelp = true
		}
	}

	// save the root flags for later use before we modify them (e.g. add runtime flags)
	rootFlags := commonutils.CopyFlagSet(rootCmd.PersistentFlags())

	grpcRuntime = grpcruntime.New(grpcruntime.WithConnectUsingK8SProxy)
	runtimeGlobalParams = grpcRuntime.GlobalParamDescs().ToParams()
	common.AddFlags(rootCmd, runtimeGlobalParams, nil, grpcRuntime)
	grpcRuntime.Init(runtimeGlobalParams)

	// evaluate flags early for runtimeGlobalParams; this will make
	// sure that all flags relevant for the grpc connection are ready
	// to be used

	err := commonutils.ParseEarlyFlags(rootCmd, os.Args[1:])
	if err != nil {
		// Analogous to cobra error message
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// ensure that the runtime flags are set from the config file
	if err = common.InitConfig(rootFlags); err != nil {
		log.Fatalf("initializing config: %v", err)
	}
	if err = common.SetFlagsForParams(rootCmd, runtimeGlobalParams, igconfig.RuntimeKey); err != nil {
		log.Fatalf("setting runtime flags from config: %v", err)
	}

	config, err := utils.KubernetesConfigFlags.ToRESTConfig()
	if err != nil {
		log.Fatalf("Creating RESTConfig: %s", err)
	}
	grpcRuntime.SetRestConfig(config)

	namespace, _ := utils.GetNamespace()
	grpcRuntime.SetDefaultValue(gadgets.K8SNamespace, namespace)

	// Execute commands that don't need the namespace early
	if !needGadgetNamespace {
		if err := rootCmd.Execute(); err != nil {
			os.Exit(1)
		}
		return
	}

	if !runtimeGlobalParams.Get(grpcruntime.ParamGadgetNamespace).IsSet() {
		gadgetNamespaces, err := utils.GetRunningGadgetNamespaces()
		if err != nil {
			log.Warnf("Failed to get gadget namespace, using \"gadget\" by default.")
		} else {
			switch len(gadgetNamespaces) {
			case 0:
				log.Warn("No running Inspektor Gadget instances found.")
			case 1:
				// Exactly one running gadget instance found, use it
				runtimeGlobalParams.Set(grpcruntime.ParamGadgetNamespace, gadgetNamespaces[0])
			default:
				// Multiple running gadget instances found, error out
				log.Warnf("Multiple running Inspektor Gadget instances found in following namespaces: %v", gadgetNamespaces)
				// avoid using wrong gadget namespace
				if !isHelp {
					os.Exit(1)
				}
			}
		}
	}

	info, err := grpcRuntime.InitDeployInfo()
	if err != nil {
		log.Warnf("Failed to load deploy info: %s", err)
	} else if err := commonutils.CheckServerVersionSkew(info.ServerVersion); err != nil {
		log.Warn(err.Error())
	}

	// add image subcommands to be added, for now only inspect is supported
	imgCommands := []*cobra.Command{
		img.NewInspectCmd(grpcRuntime),
	}

	gadgetNamespace := runtimeGlobalParams.Get(grpcruntime.ParamGadgetNamespace).AsString()

	hiddenColumnTags := []string{"runtime"}
	common.AddCommandsFromRegistry(rootCmd, grpcRuntime, hiddenColumnTags)

	common.AddInstanceCommands(rootCmd, grpcRuntime)

	// Advise and traceloop category is still being handled by CRs for now
	rootCmd.AddCommand(advise.NewAdviseCmd(gadgetNamespace))
	rootCmd.AddCommand(NewTraceloopCmd(gadgetNamespace))
	rootCmd.AddCommand(common.NewSyncCommand(grpcRuntime))
	rootCmd.AddCommand(common.NewRunCommand(rootCmd, grpcRuntime, hiddenColumnTags, common.CommandModeRun))
	rootCmd.AddCommand(common.NewRunCommand(rootCmd, grpcRuntime, hiddenColumnTags, common.CommandModeAttach))
	rootCmd.AddCommand(common.NewConfigCmd(grpcRuntime, rootFlags))
	rootCmd.AddCommand(img.NewImageCmd(grpcRuntime, imgCommands))

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
