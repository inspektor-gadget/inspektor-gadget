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
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/frontends/console"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	gadgetmanifest "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-manifest"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	clioperator "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/cli"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/combiner"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/limiter"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/otel-metrics"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/sort"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
)

type CommandMode string

const (
	CommandModeRun    CommandMode = "run"
	CommandModeAttach CommandMode = "attach"
)

var commandModesDescriptions = map[CommandMode]string{
	CommandModeRun:    "Run a gadget",
	CommandModeAttach: "Attach to a running gadget",
}

func findGadgetInstances(runtime *grpcruntime.Runtime, runtimeParams *params.Params, idOrNames []string) (instances []*api.GadgetInstance, ambiguous []string, notfound []string, retErr error) {
	gadgetInstances, err := runtime.GetGadgetInstances(context.Background(), runtimeParams)
	if err != nil {
		return nil, nil, nil, err
	}

nextName:
	for _, idOrName := range idOrNames {
		matches := 0
		var instance *api.GadgetInstance
		for _, tmpGadgetInstance := range gadgetInstances {
			if idOrName == tmpGadgetInstance.Id {
				instances = append(instances, tmpGadgetInstance)
				break nextName
			}
			// match partial ID or full name
			if tmpGadgetInstance.Name == idOrName || strings.HasPrefix(tmpGadgetInstance.Id, idOrName) {
				instance = tmpGadgetInstance
				matches++
			}
		}
		if matches > 1 {
			ambiguous = append(ambiguous, idOrName)
		} else if matches == 0 {
			notfound = append(notfound, idOrName)
		} else {
			instances = append(instances, instance)
		}
	}
	return
}

func NewRunCommand(rootCmd *cobra.Command, runtime runtime.Runtime, hiddenColumnTags []string, commandMode CommandMode) *cobra.Command {
	runtimeGlobalParams := runtime.GlobalParamDescs().ToParams()

	runtimeParams := runtime.ParamDescs().ToParams()

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
	var gadgetInstanceID string

	var inFile string

	var skipParams []string
	if commandMode == CommandModeAttach {
		skipParams = append(skipParams, "!attach")
	}

	initializedOperators := false

	preRun := func(cmd *cobra.Command, args []string) error {
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

		// set oci flags from the config file
		err = SetFlagsForParams(cmd, ociParams, config.OperatorKey+"."+ocihandler.OciHandler.Name())
		if err != nil {
			return fmt.Errorf("setting oci flags: %w", err)
		}

		// we need to re-enable flag parsing, as utils.ParseEarlyFlags() would
		// not do anything otherwise
		cmd.DisableFlagParsing = false

		// Parse flags that are known at this time, like the ones we get from the gadget descriptor
		if err := utils.ParseEarlyFlags(cmd, args); err != nil {
			return err
		}

		// Before running the gadget, we need to get the gadget info to be able to set
		// things (like params) up correctly
		actualArgs := cmd.Flags().Args()
		if len(actualArgs) == 0 {
			return cmd.ParseFlags(args)
		}

		if inFile != "" {
			return fmt.Errorf("please only specify an image OR manifest")
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

		imageName := actualArgs[0]
		if grpcrt, ok := runtime.(*grpcruntime.Runtime); ok && commandMode == CommandModeAttach {
			instances, ambiguous, notfound, err := findGadgetInstances(grpcrt, runtimeParams, []string{imageName})
			if err != nil {
				return fmt.Errorf("getting gadget instances: %w", err)
			}
			if len(notfound) > 0 || len(instances) == 0 {
				return fmt.Errorf("gadget instance not found")
			}
			if len(ambiguous) > 0 {
				return fmt.Errorf("gadget instance id or name are ambiguous")
			}
			imageName = instances[0].Id
		}

		gadgetCtx := gadgetcontext.New(
			context.Background(),
			imageName,
			gadgetcontext.WithDataOperators(ops...),
			gadgetcontext.WithUseInstance(commandMode == CommandModeAttach),
		)

		// GetOCIGadget needs at least the params from the oci handler, so let's prepare those in here
		paramValueMap := make(map[string]string)
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

		if info.Id != "" {
			gadgetInstanceID = info.Id
		}

		AddOCIFlags(cmd, &gadgetParams, skipParams, runtime)

		return cmd.ParseFlags(args)
	}

	run := func(cmd *cobra.Command, _ []string) error {
		// args from RunE still contains all flags, since we manually parsed them,
		// so we need to manually pull the remaining args here
		args := cmd.Flags().Args()

		showHelp, _ := cmd.Flags().GetBool("help")

		if len(args) == 0 && inFile == "" {
			if showHelp {
				additionalMessage := "Specify the gadget image to get more information about it"
				cmd.Long = fmt.Sprintf("%s\n\n%s", cmd.Short, additionalMessage)
			}
			return cmd.Help()
		}

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

		var image string
		if len(args) > 0 {
			image = args[0]
		}

		paramValueMap := make(map[string]string)

		if inFile != "" {
			f, err := os.Open(inFile)
			if err != nil {
				return fmt.Errorf("opening gadget runtime manifest file %s: %w", inFile, err)
			}
			specs, err := gadgetmanifest.InstanceSpecsFromReader(f)
			f.Close()
			if err != nil {
				return fmt.Errorf("reading gadget runtime manifest file %s: %w", inFile, err)
			}

			detachedParam := runtimeParams.Get("detach")
			isDetach := detachedParam != nil && detachedParam.AsBool()

			if isDetach {
				// Copy special oci params
				ociParams.CopyToMap(paramValueMap, "operator.oci.")
				return runInstanceSpecsDetached(ctx, runtime, specs, runtimeParams, paramValueMap,
					gadgetcontext.WithDataOperators(ops...),
					gadgetcontext.WithTimeout(timeoutDuration),
					gadgetcontext.WithUseInstance(false),
				)
			}

			if len(specs) > 1 {
				// output different error messages, depending on whether `--detach` is available
				if detachedParam == nil {
					return fmt.Errorf("multiple gadget instance specs found in manifest %s", inFile)
				} else {
					return fmt.Errorf("multiple gadget instance specs found in manifest %s: this is only supported in combination with --detach", inFile)
				}
			}

			spec := specs[0]
			image = spec.Image
			runtimeParams.Set("id", spec.ID)
			runtimeParams.Set("name", spec.Name)
			runtimeParams.Set("tags", strings.Join(spec.Tags, ","))

			tempParams := spec.ParamValues
			maps.Copy(tempParams, paramValueMap)
			paramValueMap = tempParams
		}

		if commandMode == CommandModeAttach {
			// the gadgetID should be present from GetGadgetInfo above
			image = gadgetInstanceID
		}

		gadgetCtx := gadgetcontext.New(
			ctx,
			image,
			gadgetcontext.WithDataOperators(ops...),
			gadgetcontext.WithTimeout(timeoutDuration),
			gadgetcontext.WithUseInstance(commandMode == CommandModeAttach),
		)

		// Write back param values
		if info != nil {
			for _, p := range info.Params {
				paramValueMap[p.Prefix+p.Key] = paramLookup[p.Prefix+p.Key].String()
			}
		}

		// Also copy special oci params
		ociParams.CopyToMap(paramValueMap, "operator.oci.")

		err := runtime.RunGadget(gadgetCtx, runtimeParams, paramValueMap)
		if err != nil {
			return err
		}
		return nil
	}

	cmd := &cobra.Command{
		Use:          string(commandMode),
		Short:        commandModesDescriptions[commandMode],
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

	if commandMode == CommandModeAttach {
		cmd.Aliases = []string{"a"}
	}

	cmd.PersistentFlags().IntVarP(
		&timeoutSeconds,
		"timeout",
		"t",
		0,
		"Number of seconds that the gadget will run for, 0 to run indefinitely",
	)

	if commandMode != CommandModeAttach {
		AddOCIFlags(cmd, ociParams, skipParams, runtime)
		cmd.PersistentFlags().StringVarP(&inFile, "file", "f", "", "path to gadget runtime manifest to apply")
	}

	AddOCIFlags(cmd, runtimeGlobalParams, skipParams, runtime)
	AddOCIFlags(cmd, runtimeParams, skipParams, runtime)

	for _, operatorParams := range opGlobalParams {
		AddOCIFlags(cmd, operatorParams, skipParams, runtime)
	}

	return cmd
}

func runInstanceSpecsDetached(
	ctx context.Context,
	runtime runtime.Runtime,
	specs []*gadgetmanifest.InstanceSpec,
	runtimeParams *params.Params,
	paramValueMap map[string]string,
	runOptions ...gadgetcontext.Option,
) error {
	var merr error
	for _, spec := range specs {
		image := spec.Image

		// Set some well-known params
		runtimeParams.Set("id", spec.ID)
		runtimeParams.Set("name", spec.Name)
		runtimeParams.Set("tags", strings.Join(spec.Tags, ","))

		maps.Copy(spec.ParamValues, paramValueMap)

		gadgetCtx := gadgetcontext.New(ctx, image, runOptions...)

		err := runtime.RunGadget(gadgetCtx, runtimeParams, spec.ParamValues)
		if err != nil {
			merr = errors.Join(merr, fmt.Errorf("running gadget from manifest file: %w", err))
		}
	}
	return merr
}

func AddOCIFlags(cmd *cobra.Command, params *params.Params, skipParams []string, runtime runtime.Runtime) {
	defer func() {
		if err := recover(); err != nil {
			panic(fmt.Sprintf("registering params for command %q: %v", cmd.Use, err))
		}
	}()
nextParam:
	for _, p := range *params {
		desc := p.Description

		if p.ValueHint != "" {
			// Try to get a value from the runtime
			if value, hasValue := runtime.GetDefaultValue(p.ValueHint); hasValue {
				p.Set(value)
			}
		}

		for _, t := range p.Tags {
			if slices.Contains(skipParams, t) {
				continue nextParam
			}
		}

		if p.PossibleValues != nil {
			desc += " [" + strings.Join(p.PossibleValues, ", ") + "]"
		}

		flag := cmd.PersistentFlags().VarPF(&Param{p}, p.Key, p.Alias, desc)
		if p.IsMandatory {
			cmd.MarkPersistentFlagRequired(p.Key)
		}

		// Allow passing a boolean flag as --foo instead of having to use --foo=true
		if p.IsBoolFlag() {
			flag.NoOptDefVal = "true"
		}
	}
}
