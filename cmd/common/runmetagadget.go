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
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/frontends/console"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	clioperator "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/cli"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/combiner"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/limiter"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/otel-logs"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/otel-metrics"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/sort"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

// TODO: make this a parameter
const metadata = `
name: bpf stats
description: TODO
homepageURL: https://inspektor-gadget.io/
documentationURL: https://www.inspektor-gadget.io/docs/latest/gadgets/TODO
sourceURL: https://github.com/inspektor-gadget/inspektor-gadget/tree/main/gadgets/TODO
annotations:
  operator.ebpf.emitstats: true
`

func NewRunMetaGadgetCommand(runtime runtime.Runtime) *cobra.Command {
	runtimeGlobalParams := runtime.GlobalParamDescs().ToParams()

	runtimeParams := runtime.ParamDescs().ToParams()

	// TODO: not really needed as those are in memory!
	ociParams := apihelpers.ToParamDescs(ocihandler.OciHandler.InstanceParams()).ToParams()

	// Add operator global flags
	opGlobalParams := make(map[string]*params.Params)
	for _, op := range operators.GetDataOperators() {
		opGlobalParams[op.Name()] = apihelpers.ToParamDescs(op.GlobalParams()).ToParams()
	}

	// gadget parameters are only available after contacting the server
	gadgetParams := make(params.Params, 0)

	var info *api.GadgetInfo
	paramLookup := map[string]*params.Param{}

	var timeoutSeconds int

	var skipParams []string

	initializedOperators := false

	preRun := func(cmd *cobra.Command, args []string) error {
		fmt.Printf("preRun\n")

		err := runtime.Init(runtimeGlobalParams)
		if err != nil {
			return fmt.Errorf("initializing runtime: %w", err)
		}
		defer runtime.Close()

		// set global operator flags from the config file
		for o, p := range opGlobalParams {
			err = SetFlagsForParams(cmd, p, config.OperatorKey+"."+o)
			if err != nil {
				return fmt.Errorf("setting operator %s flags: %w", o, err)
			}
		}

		// we need to re-enable flag parsing, as utils.ParseEarlyFlags() would
		// not do anything otherwise
		cmd.DisableFlagParsing = false

		// Parse flags that are known at this time, like the ones we get from the gadget descriptor
		if err := utils.ParseEarlyFlags(cmd, args); err != nil {
			return err
		}

		ops := make([]operators.DataOperator, 0)
		for _, op := range operators.GetDataOperators() {
			// Initialize operator
			err := op.Init(opGlobalParams[op.Name()])
			if err != nil {
				log.Warnf("error initializing operator %s: %v", op.Name(), err)
				continue
			}
			ops = append(ops, op)
		}
		ops = append(ops, clioperator.CLIOperator, combiner.CombinerOperator)
		initializedOperators = true

		gadgetCtx := gadgetcontext.New(
			context.Background(),
			"",
			gadgetcontext.WithDataOperators(ops...),
		)

		// GetOCIGadget needs at least the params from the oci handler, so let's prepare those in here
		paramValueMap := make(map[string]string)
		ociParams.Get("metadata").Set(metadata)
		ociParams.CopyToMap(paramValueMap, "operator.oci.")

		// Fetch gadget information; TODO: this can potentially be cached
		info, err = runtime.GetGadgetInfo(gadgetCtx, runtimeParams, paramValueMap)
		if err != nil {
			return fmt.Errorf("fetching gadget information: %w", err)
		}

		for _, p := range info.Params {
			// Skip already registered params (but this still lets "operator.oci.<image-operator>." pass)
			if p.Prefix == "operator.oci." {
				continue
			}
			param := apihelpers.ParamToParamDesc(p).ToParam()

			// Skip duplicate params (can happen if an operator is running on both client + server)
			if _, ok := paramLookup[p.Prefix+p.Key]; ok {
				continue
			}

			paramLookup[p.Prefix+p.Key] = param
			gadgetParams.Add(param)
		}

		AddOCIFlags(cmd, &gadgetParams, skipParams, runtime)

		return cmd.ParseFlags(args)
	}

	run := func(cmd *cobra.Command, _ []string) error {
		showHelp, _ := cmd.Flags().GetBool("help")
		if showHelp {
			return cmd.Help()
		}

		// we also manually need to check the verbose flag, as PersistentPreRunE in
		// verbose.go will not have the correct information due to manually parsing
		// the flags
		checkVerboseFlag()

		fe := console.NewFrontend()
		defer fe.Close()

		ctx := fe.GetContext()

		ops := make([]operators.DataOperator, 0)
		for _, op := range operators.GetDataOperators() {
			if !initializedOperators {
				// initialize operators if not yet done in PreRun (e.g. when -f was specified)
				err := op.Init(opGlobalParams[op.Name()])
				if err != nil {
					log.Warnf("error initializing operator %s: %v", op.Name(), err)
					continue
				}
			}
			ops = append(ops, op)
		}
		ops = append(ops, clioperator.CLIOperator, combiner.CombinerOperator)

		timeoutDuration := time.Duration(timeoutSeconds) * time.Second

		paramValueMap := make(map[string]string)

		gadgetCtx := gadgetcontext.New(
			ctx,
			"",
			gadgetcontext.WithDataOperators(ops...),
			gadgetcontext.WithTimeout(timeoutDuration),
		)

		// Write back param values
		if info != nil {
			for _, p := range info.Params {
				paramValueMap[p.Prefix+p.Key] = paramLookup[p.Prefix+p.Key].String()
			}
		}

		// Also copy special oci params
		ociParams.Get("metadata").Set(metadata)
		ociParams.CopyToMap(paramValueMap, "operator.oci.")

		err := runtime.RunGadget(gadgetCtx, runtimeParams, paramValueMap)
		if err != nil {
			return err
		}
		return nil
	}

	cmd := &cobra.Command{
		// TODO: this all should be parameters
		Use:          "stats",
		Short:        "TODO THIS AND THAT",
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
		PreRunE:            preRun,
		RunE:               run,
	}

	cmd.PersistentFlags().IntVarP(
		&timeoutSeconds,
		"timeout",
		"t",
		0,
		"Number of seconds that the gadget will run for, 0 to run indefinitely",
	)

	AddOCIFlags(cmd, runtimeGlobalParams, skipParams, runtime)
	AddOCIFlags(cmd, runtimeParams, skipParams, runtime)

	for _, operatorParams := range opGlobalParams {
		AddOCIFlags(cmd, operatorParams, skipParams, runtime)
	}

	return cmd
}
