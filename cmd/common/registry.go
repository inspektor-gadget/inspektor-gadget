// Copyright 2022-2024 The Inspektor Gadget authors
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
	"os"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	k8syaml "sigs.k8s.io/yaml"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/frontends"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/frontends/console"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
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
	kubernetesColumnPrefix = "k8s"
	runtimeColumnPrefix    = "runtime"
)

// AddCommandsFromRegistry adds all gadgets known by the registry as cobra commands as a subcommand to their categories
func AddCommandsFromRegistry(rootCmd *cobra.Command, runtime runtime.Runtime, hiddenColumnTags []string) {
	runtimeGlobalParams := runtime.GlobalParamDescs().ToParams()

	// Build lookup
	lookup := make(map[string]*cobra.Command)

	// Add operator global flags
	operatorsGlobalParamsCollection := operators.GlobalParamsCollection()
	for _, operatorParams := range operatorsGlobalParamsCollection {
		AddFlags(rootCmd, operatorParams, nil, runtime)
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
		Name: "Columns",
		Description: "The output of the gadget is formatted in human readable columns.\n  " +
			"You can optionally specify the columns to output using '-o columns=col1,col2,col3' etc.\n  " +
			"Columns can be prefixed with '+' or '-' to add or remove columns relative to the default columns.\n  " +
			"Columns 'k8s' and 'runtime' are expanded to all available columns for the respective environment.",
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

	return gadgets.OutputFormats{utils.OutputModeColumns: of}
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

const deprecationMessage = `
This built-in Gadget is deprecated and will be removed on v0.42.0 (July 2025).
Please check https://inspektor-gadget.io/docs/latest/gadgets/ to get more details on
how to switch to image-based Gadgets.

`

func buildCommandFromGadget(
	gadgetDesc gadgets.GadgetDesc,
	runtime runtime.Runtime,
	runtimeGlobalParams *params.Params,
	operatorsGlobalParamsCollection params.Collection,
	operatorsParamsCollection params.Collection,
	hiddenColumnTags []string,
) *cobra.Command {
	gType := gadgetDesc.Type()
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

	var isDeprecated bool
	if deprecated, ok := gadgetDesc.(gadgets.GadgetDeprecatedI); ok {
		isDeprecated = deprecated.IsDeprecated()
	}

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
			if isDeprecated {
				fmt.Fprint(os.Stderr, deprecationMessage)
			}

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

			// gadget parameters that are only available after contacting the server
			extraGadgetParams := make(params.Params, 0)

			// add flags
			if gType != gadgets.TypeOneShot {
				// Add timeout
				cmd.PersistentFlags().IntVarP(
					&timeout,
					"timeout",
					"t",
					0,
					"Number of seconds that the gadget will run for, 0 to disable",
				)
			}

			// Add params matching the gadget type
			extraGadgetParams.Add(*gadgets.GadgetParams(gadgetDesc, gType, parser).ToParams()...)

			// Add extra gadget flags
			AddFlags(cmd, &extraGadgetParams, skipParams, runtime)

			outputFormats.Append(gadgets.OutputFormats{
				utils.OutputModeJSON: {
					Name:        "JSON",
					Description: "The output of the gadget is returned as raw JSON",
					Transform:   nil,
				},
				utils.OutputModeJSONPretty: {
					Name:        "JSON Prettified",
					Description: "The output of the gadget is returned as prettified JSON",
					Transform:   nil,
				},
				utils.OutputModeYAML: {
					Name:        "YAML",
					Description: "The output of the gadget is returned as YAML",
					Transform:   nil,
				},
			})
			defaultOutputFormat = utils.OutputModeJSON

			// Add parser output flags
			if parser != nil {
				outputFormats.Append(buildColumnsOutputFormat(gadgetParams, parser, hiddenColumnTags))
				defaultOutputFormat = utils.OutputModeColumns

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
          This flag can be specified multiple times to combine multiple filters e.g. -F column1:value1 -F column2:value2
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

			gadgetParams.Add(extraGadgetParams...)

			return cmd.ParseFlags(args)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			// args from RunE still contains all flags, since we manually parsed them,
			// so we need to manually pull the remaining args here
			args := cmd.Flags().Args()

			if showHelp, _ := cmd.Flags().GetBool("help"); showHelp {
				return cmd.Help()
			}

			// we also manually need to check the verbose flag, as PersistentPreRunE in
			// verbose.go will not have the correct information due to manually parsing
			// the flags
			checkVerboseFlag()

			err := runtime.Init(runtimeGlobalParams)
			if err != nil {
				return fmt.Errorf("initializing runtime: %w", err)
			}
			defer runtime.Close()

			fe := console.NewFrontend()
			defer fe.Close()

			ctx := fe.GetContext()

			err = validOperators.Init(operatorsGlobalParamsCollection)
			if err != nil {
				return fmt.Errorf("initializing operators: %w", err)
			}
			defer validOperators.Close()

			timeoutDuration := time.Duration(0)

			// Handle timeout parameter by adding a timeout to the context
			if timeout != 0 {
				if gType.IsPeriodic() {
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

			gadgetCtx := gadgetcontext.NewBuiltIn(
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
				case utils.OutputModeJSON:
					transformResult = func(result any) ([]byte, error) {
						r, _ := result.([]byte)
						return r, nil
					}
				case utils.OutputModeJSONPretty:
					transformResult = func(result any) ([]byte, error) {
						var out bytes.Buffer

						err := json.Indent(&out, result.([]byte), "", "  ")
						if err != nil {
							return []byte{}, fmt.Errorf("transforming %+v: %w", result, err)
						}

						return out.Bytes(), nil
					}
				case utils.OutputModeYAML:
					transformResult = func(result any) ([]byte, error) {
						d, err := k8syaml.JSONToYAML(result.([]byte))
						if err != nil {
							return []byte{}, fmt.Errorf("transforming %+v: %w", result, err)
						}
						return []byte("---\n" + string(d)), nil
					}
				}

				if timeout == 0 && gType != gadgets.TypeTrace && gType != gadgets.TypeTraceIntervals {
					gadgetCtx.Logger().Info("Running. Press Ctrl + C to finish")
				}

				// This kind of gadgets return directly the result instead of
				// using the parser. We allow partial results, so error is only
				// returned after handling those results.
				results, err := runtime.RunBuiltInGadget(gadgetCtx)

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

			if gType.CanSort() {
				sortBy := gadgetParams.Get(gadgets.ParamSortBy).AsStringSlice()
				err := parser.SetSorting(sortBy)
				if err != nil {
					return fmt.Errorf("setting sort order: %w", err)
				}
			}

			formatter := parser.GetTextColumnsFormatter()

			requestedStandardColumns := outputModeParams == ""
			requestedColumns := make([]string, 0)

			// Check, if columns were requested relatively
			// (using only +column and -column syntax)
			addCols := make([]string, 0)
			removeCols := make([]string, 0)
			requestedAllRelativeColumns := true
			for _, col := range strings.Split(strings.ToLower(outputModeParams), ",") {
				if strings.HasPrefix(col, "+") {
					addCols = append(addCols, expandedColumns(strings.TrimPrefix(col, "+"))...)
					continue
				}
				if strings.HasPrefix(col, "-") {
					removeCols = append(removeCols, expandedColumns(strings.TrimPrefix(col, "-"))...)
					continue
				}
				requestedAllRelativeColumns = false
				requestedColumns = append(requestedColumns, expandedColumns(col)...)
			}

			// If all column requests are relative, reset requestedStandardColumns
			if requestedAllRelativeColumns {
				requestedStandardColumns = true
			}

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
				requestedColumns = append(requestedColumns, parser.GetDefaultColumns(hiddenTags...)...)
			}

			// Add/remove relative column requests
			if len(addCols) > 0 || len(removeCols) > 0 {
				newRequestedColumns := make([]string, 0)
				for _, col := range requestedColumns {
					if containsColumn(removeCols, col) {
						continue
					}
					newRequestedColumns = append(newRequestedColumns, col)
				}
				// add remaining columns
				for _, col := range addCols {
					if containsColumn(newRequestedColumns, col) || containsColumn(removeCols, col) {
						continue
					}
					newRequestedColumns = append(newRequestedColumns, col)
				}
				requestedColumns = newRequestedColumns
			}

			// sort columns by runtime and kubernetes columns
			if requestedAllRelativeColumns {
				stableSortByPrefix(runtimeColumnPrefix, requestedColumns)
				stableSortByPrefix(kubernetesColumnPrefix, requestedColumns)
			}

			if len(requestedColumns) == 0 {
				log.Warn("no columns requested")
				requestedColumns = parser.GetDefaultColumns(hiddenColumnTags...)
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
			case utils.OutputModeColumns:
				formatter.SetEventCallback(fe.Output)

				// Enable additional output, if the gadget supports it (e.g. profile/cpu)
				//  TODO: This can be optimized later on
				formatter.SetEnableExtraLines(true)

				parser.SetEventCallback(formatter.EventHandlerFunc())
				if gType.IsPeriodic() {
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
			case utils.OutputModeJSON:
				jsonCallback := printEventAsJSONFn(fe)
				parser.SetEventCallback(jsonCallback)
			case utils.OutputModeJSONPretty:
				jsonPrettyCallback := printEventAsJSONPrettyFn(fe)
				parser.SetEventCallback(jsonPrettyCallback)
			case utils.OutputModeYAML:
				yamlCallback := printEventAsYAMLFn(fe)
				parser.SetEventCallback(yamlCallback)
			}

			// Gadgets with parser don't return anything, they provide the
			// output via the parser
			_, err = runtime.RunBuiltInGadget(gadgetCtx)
			if err != nil {
				return fmt.Errorf("running gadget: %w", err)
			}

			return nil
		},
	}

	// Add flags known at this time, others will be added in PreRunE

	// Add runtime flags
	AddFlags(cmd, runtimeParams, skipParams, runtime)

	// Add gadget flags
	AddFlags(cmd, gadgetParams, skipParams, runtime)

	// Add operator flags
	for _, operatorParams := range operatorsParamsCollection {
		AddFlags(cmd, operatorParams, skipParams, runtime)
	}

	return cmd
}

func containsColumn(columns []string, column string) bool {
	for _, c := range columns {
		if strings.EqualFold(c, column) {
			return true
		}
	}
	return false
}

func expandedColumns(col string) []string {
	switch col {
	case kubernetesColumnPrefix:
		return utils.GetKubernetesColumns()
	case runtimeColumnPrefix:
		return utils.GetContainerRuntimeColumns()
	case "":
		return []string{}
	default:
		return []string{col}
	}
}

func stableSortByPrefix(prefix string, columns []string) {
	prefix = prefix + "."
	sort.SliceStable(columns, func(i, j int) bool {
		if strings.HasPrefix(columns[i], prefix) && !strings.HasPrefix(columns[j], prefix) {
			return true
		}
		return i < j
	})
}

func mustSkip(skipParams []params.ValueHint, valueHint params.ValueHint) bool {
	for _, param := range skipParams {
		if param == valueHint {
			return true
		}
	}
	return false
}

func AddFlags(cmd *cobra.Command, params *params.Params, skipParams []params.ValueHint, runtime runtime.Runtime) {
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
