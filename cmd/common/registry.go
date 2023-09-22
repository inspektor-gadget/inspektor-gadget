// Copyright 2022-2023 The Inspektor Gadget authors
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
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	k8syaml "sigs.k8s.io/yaml"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/frontends"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/frontends/console"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

const (
	OutputModeColumns    = "columns"
	OutputModeJSON       = "json"
	OutputModeJSONPretty = "jsonpretty"
	OutputModeYAML       = "yaml"
)

// AddCommandsFromRegistry adds all gadgets known by the registry as cobra commands as a subcommand to their categories
func AddCommandsFromRegistry(rootCmd *cobra.Command, runtime runtime.Runtime, hiddenColumnTags []string) {
	runtimeGlobalParams := runtime.GlobalParamDescs().ToParams()

	// Build lookup
	lookup := make(map[string]*cobra.Command)

	// Add global runtime flags
	addFlags(rootCmd, runtimeGlobalParams, nil, runtime)

	// Add operator global flags
	operatorsGlobalParamsCollection := operators.GlobalParamsCollection()
	for _, operatorParams := range operatorsGlobalParamsCollection {
		addFlags(rootCmd, operatorParams, nil, runtime)
	}

	// Add all known gadgets to cobra in their respective categories
	categories := gadgets.GetCategories()
	catalog, _ := runtime.GetCatalog()
	if catalog == nil {
		return
	}

	for _, gadgetInfo := range catalog.Gadgets {
		gadgetDesc := gadgetregistry.Get(gadgetInfo.Category, gadgetInfo.Name)
		if gadgetDesc == nil {
			// This only happens, if the gadget is only known to the remote side. In this case, let's skip for now. In
			// the future, we could at least support raw output for these unknown gadgets.
			continue
		}

		categoryCmd := rootCmd
		if gadgetInfo.Category != gadgets.CategoryNone {
			cmd, ok := lookup[gadgetInfo.Category]
			if !ok {
				// Category not found, add it - if a gadget category is unknown, we'll still add it, even if we don't
				// have a description.
				categoryDescription := categories[gadgetInfo.Category]
				cmd = &cobra.Command{
					Use:   gadgetInfo.Category,
					Short: categoryDescription,
				}
				rootCmd.AddCommand(cmd)
				lookup[gadgetInfo.Category] = cmd
			}
			categoryCmd = cmd
		}
		categoryCmd.AddCommand(buildCommandFromGadget(
			gadgetDesc,
			runtime,
			runtimeGlobalParams,
			operatorsGlobalParamsCollection,
			gadgetInfo.OperatorParamsCollection.ToParams(),
			hiddenColumnTags,
		))
	}
}

func buildColumnsOutputFormat(gadgetParams *params.Params, parser parser.Parser, hiddenColumnTags []string) gadgets.OutputFormats {
	paramTags := make(map[string]string)
	if gadgetParams != nil {
		for _, param := range *gadgetParams {
			if param.TypeHint == params.TypeBool {
				paramTags["param:"+strings.ToLower(param.Key)] = param.Key
			}
		}
	}
	hasAnyTag := func(columnTags []string) (string, bool) {
		for _, columnTag := range columnTags {
			if key, ok := paramTags[columnTag]; ok {
				return key, true
			}
		}
		return "", false
	}

	of := gadgets.OutputFormat{
		Name:        "Columns",
		Description: "The output of the gadget is formatted in human readable columns.\n  You can optionally specify the columns to output using '-o columns=col1,col2,col3' etc.",
	}

	var out strings.Builder
	fmt.Fprintf(&out, "\n    Available columns:\n")

	columnAttributes := parser.GetColumnAttributes()
	sort.Slice(columnAttributes, func(i, j int) bool {
		return columnAttributes[i].Name < columnAttributes[j].Name
	})
	for _, attrs := range columnAttributes {
		fmt.Fprintf(&out, "      %s", attrs.Name)
		if attrs.Description != "" {
			fmt.Fprintf(&out, "%s", attrs.Description)
		}
		if paramKey, ok := hasAnyTag(attrs.Tags); ok {
			fmt.Fprintf(&out, " (requires --%s)", paramKey)
		}
		fmt.Fprintf(&out, "\n")
	}
	fmt.Fprintf(&out, "    Default columns: %s\n", strings.Join(parser.GetDefaultColumns(hiddenColumnTags...), ","))

	of.Description += out.String()

	return gadgets.OutputFormats{OutputModeColumns: of}
}

func buildOutputFormatsHelp(outputFormats gadgets.OutputFormats) []string {
	var outputFormatsHelp []string
	var supportedOutputFormats []string

	for ofKey, of := range outputFormats {
		supportedOutputFormats = append(supportedOutputFormats, ofKey)
		desc := fmt.Sprintf("%s (%s)", of.Name, ofKey)
		if of.Description != "" {
			desc += fmt.Sprintf("\n  %s", of.Description)
		}
		outputFormatsHelp = append(outputFormatsHelp, desc)
	}
	sort.Strings(outputFormatsHelp)
	outputFormatsHelp = append([]string{
		fmt.Sprintf("Output format (%s).", strings.Join(supportedOutputFormats, ", ")),
		"",
	}, outputFormatsHelp...)
	return outputFormatsHelp
}

func buildCommandFromGadget(
	gadgetDesc gadgets.GadgetDesc,
	runtime runtime.Runtime,
	runtimeGlobalParams *params.Params,
	operatorsGlobalParamsCollection params.Collection,
	operatorsParamsCollection params.Collection,
	hiddenColumnTags []string,
) *cobra.Command {
	var outputMode string
	var filters []string
	var timeout int

	var skipParams []params.ValueHint
	if skipParamsInterface, ok := gadgetDesc.(gadgets.GadgetDescSkipParams); ok {
		skipParams = skipParamsInterface.SkipParams()
	}

	outputFormats := gadgets.OutputFormats{}
	defaultOutputFormat := ""

	// Instantiate parser - this is important to do, because we might apply filters and such to this instance
	parser := gadgetDesc.Parser()

	// Instantiate runtime params
	runtimeParams := runtime.ParamDescs().ToParams()

	// Instantiate gadget params - this is important, because the params get filled out by cobra
	gadgetParams := gadgetDesc.ParamDescs().ToParams()

	// Get per gadget operators
	validOperators := operators.GetOperatorsForGadget(gadgetDesc)

	// TODO: Combine remote operator params with locally available ones
	//  Example use case: setting default namespace for kubernetes

	cmd := &cobra.Command{
		Use:          gadgetDesc.Name(),
		Short:        gadgetDesc.Description(),
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
			// we need to re-enable flag parsing, as cmd.ParseFlags() would not
			// do anything otherwise
			cmd.DisableFlagParsing = false
			return cmd.ParseFlags(args)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			// args from RunE still contains all flags, since we manually parsed them,
			// so we need to manually pull the remaining args here
			args := cmd.Flags().Args()

			// we also manually need to check the verbose flag, as PersistentPreRunE in
			// verbose.go will not have the correct information due to manually parsing
			// the flags
			checkVerboseFlag()

			if c, ok := gadgetDesc.(gadgets.GadgetDescCustomParser); ok {
				var err error
				parser, err = c.CustomParser(gadgetParams, cmd.Flags().Args())
				if err != nil {
					return fmt.Errorf("calling custom parser: %w", err)
				}
			}

			if parser != nil {
				outputFormats.Append(buildColumnsOutputFormat(gadgetParams, parser, hiddenColumnTags))
				outputFormatsHelp := buildOutputFormatsHelp(outputFormats)
				cmd.Flags().Lookup("output").Usage = strings.Join(outputFormatsHelp, "\n") + "\n\n"
				cmd.Flags().Lookup("output").DefValue = "columns"
			}

			if showHelp, _ := cmd.Flags().GetBool("help"); showHelp {
				return cmd.Help()
			}

			err := runtime.Init(runtimeGlobalParams)
			if err != nil {
				return fmt.Errorf("initializing runtime: %w", err)
			}
			defer runtime.Close()

			err = validOperators.Init(operatorsGlobalParamsCollection)
			if err != nil {
				return fmt.Errorf("initializing operators: %w", err)
			}
			defer validOperators.Close()

			fe := console.NewFrontend()
			defer fe.Close()

			ctx := fe.GetContext()

			timeoutDuration := time.Duration(0)

			// Handle timeout parameter by adding a timeout to the context
			if timeout != 0 {
				if gadgetDesc.Type().IsPeriodic() {
					interval := gadgetParams.Get(gadgets.ParamInterval).AsInt()
					if timeout < interval {
						return fmt.Errorf("timeout must be greater than interval")
					}
					if timeout%interval != 0 {
						return fmt.Errorf("timeout must be a multiple of interval")
					}
				}

				timeoutDuration = time.Duration(timeout) * time.Second
			}

			gadgetCtx := gadgetcontext.New(
				ctx,
				"",
				runtime,
				runtimeParams,
				gadgetDesc,
				gadgetParams,
				args,
				operatorsParamsCollection,
				parser,
				logger.DefaultLogger(),
				timeoutDuration,
			)
			defer gadgetCtx.Cancel()

			outputModeInfo := strings.SplitN(outputMode, "=", 2)
			outputModeName := outputModeInfo[0]
			outputModeParams := ""
			if len(outputModeInfo) > 1 {
				outputModeParams = outputModeInfo[1]
			}

			if parser == nil {
				var transformResult func(any) ([]byte, error)

				switch outputModeName {
				default:
					transformer, ok := gadgetDesc.(gadgets.GadgetOutputFormats)
					if !ok {
						return fmt.Errorf("gadget does not provide output formats")
					}
					formats, _ := transformer.OutputFormats()
					if _, ok := formats[outputModeName]; !ok {
						return fmt.Errorf("invalid output mode %q", outputModeName)
					}

					transformResult = formats[outputModeName].Transform
				case OutputModeJSON:
					transformResult = func(result any) ([]byte, error) {
						r, _ := result.([]byte)
						return r, nil
					}
				case OutputModeJSONPretty:
					printEventAsJSONPrettyFn(fe)
				case OutputModeYAML:
					printEventAsYAMLFn(fe)
				}

				gType := gadgetDesc.Type()
				if timeout == 0 && gType != gadgets.TypeTrace && gType != gadgets.TypeTraceIntervals {
					gadgetCtx.Logger().Info("Running. Press Ctrl + C to finish")
				}

				// This kind of gadgets return directly the result instead of
				// using the parser. We allow partial results, so error is only
				// returned after handling those results.
				results, err := runtime.RunGadget(gadgetCtx)

				for node, result := range results {
					if result.Error != nil {
						continue
					}
					transformed, err := transformResult(result.Payload)
					if err != nil {
						gadgetCtx.Logger().Warnf("transform result for %q failed: %v", node, err)
						continue
					}
					results[node].Payload = transformed
				}

				if len(results) == 1 {
					// still need to iterate as we don't necessarily know the key
					for _, result := range results {
						fe.Output(string(result.Payload))
					}
				} else {
					format := "%s: %s"
					for _, result := range results {
						// Check, whether we have a multi-line payload and adjust the output accordingly
						if bytes.Contains(result.Payload, []byte("\n")) {
							format = "\n---\n%s:\n%s"
							break
						}
					}
					for key, result := range results {
						fe.Output(fmt.Sprintf(format, key, string(result.Payload)))
					}
				}

				return err
			}

			// Add filters if requested
			if len(filters) > 0 {
				err = parser.SetFilters(filters)
				if err != nil {
					return fmt.Errorf("setting filters: %w", err)
				}
			}

			if gadgetDesc.Type().CanSort() {
				sortBy := gadgetParams.Get(gadgets.ParamSortBy).AsStringSlice()
				err := parser.SetSorting(sortBy)
				if err != nil {
					return fmt.Errorf("setting sort order: %w", err)
				}
			}

			formatter := parser.GetTextColumnsFormatter()

			requestedStandardColumns := outputModeParams == ""
			requestedColumns := strings.Split(outputModeParams, ",")

			// If the standard columns are requested, hide columns that would be empty without specific features
			// (bool params) enabled
			if requestedStandardColumns {
				var hiddenTags []string
				if gadgetParams != nil {
					for _, param := range *gadgetParams {
						if param.TypeHint == params.TypeBool {
							if !param.AsBool() {
								hiddenTags = append(hiddenTags, "param:"+strings.ToLower(param.Key))
							}
						}
					}
				}
				// hide columns by tag (e.g. kubernetes, runtime) if requested by the caller
				if len(hiddenColumnTags) > 0 {
					hiddenTags = append(hiddenTags, hiddenColumnTags...)
				}
				requestedColumns = parser.GetDefaultColumns(hiddenTags...)
			}

			valid, invalid := parser.VerifyColumnNames(requestedColumns)

			for _, c := range invalid {
				log.Warnf("column %q not found", c)
			}

			if err := formatter.SetShowColumns(valid); err != nil {
				return err
			}

			parser.SetLogCallback(fe.Logf)

			// Wire up callbacks before handing over to runtime depending on the output mode
			switch outputModeName {
			default:
				transformer, ok := gadgetDesc.(gadgets.GadgetOutputFormats)
				if !ok {
					return fmt.Errorf("gadget does not provide output formats")
				}
				formats, _ := transformer.OutputFormats()
				if _, ok := formats[outputModeName]; !ok {
					return fmt.Errorf("invalid output mode %q", outputModeName)
				}

				format := formats[outputModeName]

				if format.RequiresCombinedResult {
					parser.EnableCombiner()
				}

				transformResult := format.Transform
				parser.SetEventCallback(func(ev any) {
					transformed, err := transformResult(ev)
					if err != nil {
						fe.Logf(logger.WarnLevel, "could not transform event: %v", err)
						return
					}
					fe.Output(string(transformed))
				})
			case OutputModeColumns:
				formatter.SetEventCallback(fe.Output)

				// Enable additional output, if the gadget supports it (e.g. profile/cpu)
				//  TODO: This can be optimized later on
				formatter.SetEnableExtraLines(true)

				parser.SetEventCallback(formatter.EventHandlerFunc())
				if gadgetDesc.Type().IsPeriodic() {
					// In case of periodic outputting gadgets, this is done as full table output, and we need to
					// clear the screen for every interval, that's why we add fe.Clear here
					parser.SetEventCallback(formatter.EventHandlerFuncArray(
						fe.Clear,
						func() {
							fe.Output(formatter.FormatHeader())
						},
					))

					// Print first header while we wait for input
					if fe.IsTerminal() {
						fe.Clear()
						fe.Output(formatter.FormatHeader())
					}
					break
				}
				fe.Output(formatter.FormatHeader())
				parser.SetEventCallback(formatter.EventHandlerFuncArray())
			case OutputModeJSON:
				jsonCallback := printEventAsJSONFn(fe)
				if cjson, ok := gadgetDesc.(gadgets.GadgetJSONConverter); ok {
					jsonCallback = cjson.JSONConverter(gadgetParams, fe)
				}
				parser.SetEventCallback(jsonCallback)
			case OutputModeJSONPretty:
				jsonPrettyCallback := printEventAsJSONPrettyFn(fe)
				if cjson, ok := gadgetDesc.(gadgets.GadgetJSONPrettyConverter); ok {
					jsonPrettyCallback = cjson.JSONPrettyConverter(gadgetParams, fe)
				}
				parser.SetEventCallback(jsonPrettyCallback)
			case OutputModeYAML:
				yamlCallback := printEventAsYAMLFn(fe)
				if cyaml, ok := gadgetDesc.(gadgets.GadgetYAMLConverter); ok {
					yamlCallback = cyaml.YAMLConverter(gadgetParams, fe)
				}
				parser.SetEventCallback(yamlCallback)
			}

			// Gadgets with parser don't return anything, they provide the
			// output via the parser
			_, err = runtime.RunGadget(gadgetCtx)
			if err != nil {
				return fmt.Errorf("running gadget: %w", err)
			}

			return nil
		},
	}

	if gadgetDesc.Type() != gadgets.TypeOneShot {
		// Add timeout
		cmd.PersistentFlags().IntVarP(
			&timeout,
			"timeout",
			"t",
			0,
			"Number of seconds that the gadget will run for, 0 to disable",
		)
	}

	outputFormats.Append(gadgets.OutputFormats{
		"json": {
			Name:        "JSON",
			Description: "The output of the gadget is returned as raw JSON",
			Transform:   nil,
		},
		OutputModeJSONPretty: {
			Name:        "JSON Prettified",
			Description: "The output of the gadget is returned as prettified JSON",
			Transform:   nil,
		},
		OutputModeYAML: {
			Name:        "YAML",
			Description: "The output of the gadget is returned as YAML",
			Transform:   nil,
		},
	})
	defaultOutputFormat = "json"

	// Add parser output flags
	if parser != nil {
		outputFormats.Append(buildColumnsOutputFormat(gadgetParams, parser, hiddenColumnTags))
	}
	_, hasCustomParser := gadgetDesc.(gadgets.GadgetDescCustomParser)

	if parser != nil || hasCustomParser {
		defaultOutputFormat = "columns"

		cmd.PersistentFlags().StringSliceVarP(
			&filters,
			"filter", "F",
			[]string{},
			`Filter rules
  A filter can match any column using the following syntax
    columnName:value       - matches, if the content of columnName equals exactly value
    columnName:!value      - matches, if the content of columnName does not equal exactly value
    columnName:>=value     - matches, if the content of columnName is greater than or equal to the value
    columnName:>value      - matches, if the content of columnName is greater than the value
    columnName:<=value     - matches, if the content of columnName is less than or equal to the value
    columnName:<value      - matches, if the content of columnName is less than the value
    columnName:~value      - matches, if the content of columnName matches the regular expression 'value'
                             see [https://github.com/google/re2/wiki/Syntax] for more information on the syntax
`,
		)
	}

	// Add alternative output formats available in the gadgets
	if outputFormatInterface, ok := gadgetDesc.(gadgets.GadgetOutputFormats); ok {
		formats, defaultFormat := outputFormatInterface.OutputFormats()
		outputFormats.Append(formats)
		defaultOutputFormat = defaultFormat
	}

	outputFormatsHelp := buildOutputFormatsHelp(outputFormats)

	cmd.PersistentFlags().StringVarP(
		&outputMode,
		"output",
		"o",
		defaultOutputFormat,
		strings.Join(outputFormatsHelp, "\n")+"\n\n",
	)

	// Add params matching the gadget type
	gadgetParams.Add(*gadgets.GadgetParams(gadgetDesc, parser).ToParams()...)

	// Add runtime flags
	addFlags(cmd, runtimeParams, skipParams, runtime)

	// Add gadget flags
	addFlags(cmd, gadgetParams, skipParams, runtime)

	// Add operator flags
	for _, operatorParams := range operatorsParamsCollection {
		addFlags(cmd, operatorParams, skipParams, runtime)
	}
	return cmd
}

func mustSkip(skipParams []params.ValueHint, valueHint params.ValueHint) bool {
	for _, param := range skipParams {
		if param == valueHint {
			return true
		}
	}
	return false
}

func addFlags(cmd *cobra.Command, params *params.Params, skipParams []params.ValueHint, runtime runtime.Runtime) {
	defer func() {
		if err := recover(); err != nil {
			panic(fmt.Sprintf("registering params for command %q: %v", cmd.Use, err))
		}
	}()
	for _, p := range *params {
		desc := p.Description

		if p.ValueHint != "" {
			if mustSkip(skipParams, p.ValueHint) {
				// don't expose this parameter
				continue
			}

			// Try to get a value from the runtime
			if value, hasValue := runtime.GetDefaultValue(p.ValueHint); hasValue {
				p.Set(value)
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

func printEventAsJSONFn(fe frontends.Frontend) func(ev any) {
	return func(ev any) {
		d, err := json.Marshal(ev)
		if err != nil {
			fe.Logf(logger.WarnLevel, "marshaling %+v: %s", ev, err)
			return
		}
		fe.Output(string(d))
	}
}

func printEventAsJSONPrettyFn(fe frontends.Frontend) func(ev any) {
	return func(ev any) {
		d, err := json.MarshalIndent(ev, "", "  ")
		if err != nil {
			fe.Logf(logger.WarnLevel, "marshaling %+v: %s", ev, err)
			return
		}
		fe.Output(string(d))
	}
}

func printEventAsYAMLFn(fe frontends.Frontend) func(ev any) {
	return func(ev any) {
		d, err := k8syaml.Marshal(ev)
		if err != nil {
			fe.Logf(logger.WarnLevel, "marshaling %+v: %s", ev, err)
			return
		}
		fe.Output("---\n" + string(d))
	}
}
