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
	"net/http"
	_ "net/http/pprof"
	"runtime"
	"runtime/debug"
	"time"

	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	// Import this early to set the enrivonment variable before any other package is imported
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/environment/local"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/image"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/ig/containers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/experimental"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"

	// This is a blank include that actually imports all gadgets
	// TODO: traceloop is imported separately because it is not in all-gadgets
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/all-gadgets"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/traceloop/tracer"

	// Another blank import for the used operator
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/btfgen"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/filter"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/formatters"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/localmanager"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/prometheus"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/socketenricher"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/sort"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/uidgidresolver"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ustack"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/wasm"
)

func main() {
	go func() {
		for {
			runtime.GC()
			debug.FreeOSMemory()
			time.Sleep(1 * time.Second)
		}
	}()

	go func() {
		addr := os.Getenv("PPROF_ADDR")
		if addr == "" {
			addr = "localhost:6060"
		}
		http.ListenAndServe(addr, nil)
	}()

	if experimental.Enabled() {
		log.Info("Experimental features enabled")
	}

	rootCmd := &cobra.Command{
		Use:   "ig",
		Short: "Collection of gadgets for containers",
	}
	common.AddConfigFlag(rootCmd)
	common.AddVerboseFlag(rootCmd)

	host.AddFlags(rootCmd)

	rootCmd.AddCommand(
		containers.NewListContainersCmd(),
		common.NewVersionCmd(),
	)

	rootCmd.PersistentFlags().String("pprof-addr", "", "Starts a pprof server for profiling at the given address (e.g., 'localhost:6060'), leave empty to disable (default).")

	// evaluate flags early; this will make sure that flags for host are evaluated before
	// calling host.Init()
	err := commonutils.ParseEarlyFlags(rootCmd, os.Args[1:])
	if err != nil {
		// Analogous to cobra error message
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// save the root flags for later use before we modify them (e.g. add runtime flags)
	rootFlags := commonutils.CopyFlagSet(rootCmd.PersistentFlags())

	runtime := local.New()

	// ensure that the runtime flags are set from the config file
	if err = common.InitConfig(rootFlags); err != nil {
		log.Fatalf("initializing config: %v", err)
	}
	if err = common.SetFlagsForParams(rootCmd, runtime.GlobalParamDescs().ToParams(), config.RuntimeKey); err != nil {
		log.Fatalf("setting runtime flags from config: %v", err)
	}

	hiddenColumnTags := []string{"kubernetes"}
	common.AddCommandsFromRegistry(rootCmd, runtime, hiddenColumnTags)

	operators.RegisterDataOperator(ocihandler.OciHandler)

	rootCmd.AddCommand(newDaemonCommand(runtime))
	rootCmd.AddCommand(image.NewImageCmd())
	rootCmd.AddCommand(common.NewLoginCmd())
	rootCmd.AddCommand(common.NewLogoutCmd())
	rootCmd.AddCommand(common.NewRunCommand(rootCmd, runtime, hiddenColumnTags, common.CommandModeRun))
	rootCmd.AddCommand(common.NewConfigCmd(runtime, rootFlags))

	pprofAddr, _ := rootCmd.PersistentFlags().GetString("pprof-addr")
	if pprofAddr != "" {
		go func() {
			if err := http.ListenAndServe(pprofAddr, nil); err != nil {
				log.Fatalf("starting pprof server: %v", err)
			}
		}()
	}
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
