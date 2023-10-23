// Copyright 2023 The Inspektor Gadget authors
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
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/all-gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/environment"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/experimental"
)

var infoSkipCommands = []string{"version"}

func main() {
	if experimental.Enabled() {
		log.Info("Experimental features enabled")
	}

	rootCmd := &cobra.Command{
		Use:   filepath.Base(os.Args[0]),
		Short: "Collection of gadgets for containers",
	}
	common.AddVerboseFlag(rootCmd)

	skipInfo := false
	for _, arg := range os.Args[1:] {
		for _, skipCmd := range infoSkipCommands {
			if strings.ToLower(arg) == skipCmd {
				skipInfo = true
			}
		}
	}

	rootCmd.AddCommand(common.NewVersionCmd())

	runtime := grpcruntime.New()

	runtimeGlobalParams := runtime.GlobalParamDescs().ToParams()
	common.AddFlags(rootCmd, runtimeGlobalParams, nil, runtime)
	err := runtime.Init(runtimeGlobalParams)
	if err != nil {
		log.Fatalf("initializing runtime: %v", err)
	}

	if !skipInfo {
		// evaluate flags early for runtimeGlobalFlags; this will make
		// sure that --remote-address has already been parsed when calling
		// InitDeployInfo(), so it can target the specified address

		// Do not error out on unknown flags, but still validate currently
		// known ones.
		// Other flags will be validated in the `Execute()` call and unknown
		// ones will be rejected
		rootCmd.FParseErrWhitelist.UnknownFlags = true
		err := rootCmd.ParseFlags(os.Args[1:])
		if err != nil {
			// Analogous to cobra error message
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		rootCmd.FParseErrWhitelist.UnknownFlags = false
		runtime.InitDeployInfo()
	}

	hiddenColumnTags := []string{"kubernetes"}
	common.AddCommandsFromRegistry(rootCmd, runtime, hiddenColumnTags)

	rootCmd.AddCommand(common.NewSyncCommand(runtime))

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	environment.Environment = environment.Local
}
