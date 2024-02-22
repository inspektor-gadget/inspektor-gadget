// Copyright 2024 The Inspektor Gadget authors
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

package common

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/frontends/console"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

func NewRunCommand(rootCmd *cobra.Command, runtime runtime.Runtime, hiddenColumnTags []string) *cobra.Command {
	runtimeGlobalParams := runtime.GlobalParamDescs().ToParams()
	runtime.Init(runtimeGlobalParams)

	// Add operator global flags
	operatorsGlobalParamsCollection := operators.GlobalParamsCollection()

	// gadget parameters that are only available after contacting the server
	gadgetParams := make(params.Params, 0)
	ociParams := operators.OCIParamDescs().ToParams()

	cmd := &cobra.Command{
		Use:          "run-experimental",
		Short:        "run gadget",
		SilenceUsage: true, // do not print usage when there is an error
		// We have to disable flag parsing in here to be able to handle certain
		// flags more dynamically and have `--help` also react to those changes.
		// Instead, we need to manually
		// * call cmd.ParseFlags()
		// * handle `--help` after changing the params dynamically
		// * handle everything that could have been handled inside
		//   `PersistentPreRun(E)` of a parent cmd, as the flags wouldn't have
		//   been parsed there (e.g. --verbose)
		DisableFlagParsing: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			err := runtime.Init(runtimeGlobalParams)
			if err != nil {
				return fmt.Errorf("initializing runtime: %w", err)
			}
			defer runtime.Close()

			// we need to re-enable flag parsing, as utils.ParseEarlyFlags() would
			// not do anything otherwise
			cmd.DisableFlagParsing = false

			// Parse flags that are known at this time, like the ones we get from the gadget descriptor
			if err := utils.ParseEarlyFlags(cmd, args); err != nil {
				return err
			}

			// Before running the gadget, we need to get the gadget info to perform
			// different tasks like creating the parser and setting flags for the
			// gadget's parameters.
			actualArgs := cmd.Flags().Args()

			gadgetCtx := gadgetcontext.NewSimple(
				context.Background(), actualArgs[0], logger.DefaultLogger(), ociParams, nil,
			)

			// Fetch gadget information; TODO: this can potentially be cached
			info, err := runtime.GetOCIGadgetInfo(gadgetCtx, nil, nil)
			if err != nil {
				return fmt.Errorf("fetching gadget information: %w", err)
			}

			fmt.Printf("PreRun: Params are: %+v\n", info.Params)

			for _, p := range info.Params {
				gadgetParams.Add(api.ParamToParamDesc(p).ToParam())
			}

			AddFlags(cmd, &gadgetParams, nil, runtime)

			return cmd.ParseFlags(args)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			// args from RunE still contains all flags, since we manually parsed them,
			// so we need to manually pull the remaining args here
			args := cmd.Flags().Args()

			if len(args) == 0 {
				if showHelp, _ := cmd.Flags().GetBool("help"); showHelp {
					additionalMessage := "Specify the gadget image to get more information about it"
					cmd.Long = fmt.Sprintf("%s\n\n%s", cmd.Short, additionalMessage)
				}
				return cmd.Help()
			}

			if showHelp, _ := cmd.Flags().GetBool("help"); showHelp {
				return cmd.Help()
			}

			// we also manually need to check the verbose flag, as PersistentPreRunE in
			// verbose.go will not have the correct information due to manually parsing
			// the flags
			checkVerboseFlag()

			fe := console.NewFrontend()
			defer fe.Close()

			ctx := fe.GetContext()

			gadgetCtx := gadgetcontext.NewSimple(
				ctx, args[0], logger.DefaultLogger(), ociParams, &gadgetParams,
			)

			// parameters?

			fmt.Printf("gadget params are: %+v\n", gadgetParams)
			fmt.Printf("oci params are: %+v\n", ociParams)

			err := runtime.RunOCIGadget(gadgetCtx)
			if err != nil {
				return err
			}
			return nil
		},
	}

	for _, operatorParams := range operatorsGlobalParamsCollection {
		AddFlags(cmd, operatorParams, nil, runtime)
	}

	AddFlags(cmd, ociParams, nil, runtime)

	return cmd
}
