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
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/frontends"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/frontends/console"
	cols "github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

const (
	OutputModeColumns = "columns"
	OutputModeJSON    = "json"
)

// AddCommandsFromRegistry adds all gadgets known by the registry as cobra commands as a subcommand to their categories
func AddCommandsFromRegistry(rootCmd *cobra.Command, runtime runtime.Runtime, columnFilters []cols.ColumnFilter) {
	runtimeParams := runtime.GlobalParamDescs().ToParams()

	// Build lookup
	lookup := make(map[string]*cobra.Command)

	// Add runtime flags
	addFlags(rootCmd, runtimeParams)

	// Add operator global flags
	operatorsParamsCollection := operators.GlobalParamsCollection()
	for _, operatorParams := range operatorsParamsCollection {
		addFlags(rootCmd, operatorParams)
	}

	// Add all known gadgets to cobra in their respective categories
	categories := gadgets.GetCategories()
	for _, gadgetDesc := range gadgetregistry.GetAll() {
		categoryCmd := rootCmd
		if gadgetDesc.Category() != gadgets.CategoryNone {
			cmd, ok := lookup[gadgetDesc.Category()]
			if !ok {
				// Category not found, add it
				categoryDescription, ok := categories[gadgetDesc.Category()]
				if !ok {
					panic(fmt.Errorf("category unknown: %q", gadgetDesc.Category()))
				}
				cmd = &cobra.Command{
					Use:   gadgetDesc.Category(),
					Short: categoryDescription,
				}
				rootCmd.AddCommand(cmd)
				lookup[gadgetDesc.Category()] = cmd
			}
			categoryCmd = cmd
		}
		categoryCmd.AddCommand(buildCommandFromGadget(
			gadgetDesc,
			columnFilters,
			runtime,
			runtimeParams,
			operatorsParamsCollection,
		))
	}
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
	columnFilters []cols.ColumnFilter,
	runtime runtime.Runtime,
	runtimeParams *params.Params,
	operatorsParamsCollection params.Collection,
) *cobra.Command {
	var outputMode string
	var verbose bool
	var filters []string
	var timeout int

	outputFormats := gadgets.OutputFormats{}
	defaultOutputFormat := ""

	// Instantiate parser - this is important to do, because we might apply filters and such to this instance
	parser := gadgetDesc.Parser()
	if parser != nil && columnFilters != nil {
		parser.SetColumnFilters(columnFilters...)
	}

	// Instantiate gadget params - this is important, because the params get filled out by cobra
	gadgetParams := gadgetDesc.ParamDescs().ToParams()

	// Get per gadget operator params
	validOperators := operators.GetOperatorsForGadget(gadgetDesc)
	operatorsParamCollection := validOperators.ParamCollection()

	cmd := &cobra.Command{
		Use:          gadgetDesc.Name(),
		Short:        gadgetDesc.Description(),
		SilenceUsage: true, // do not print usage when there is an error
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if verbose {
				log.SetLevel(log.DebugLevel)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			err := runtime.Init(runtimeParams)
			if err != nil {
				return fmt.Errorf("initializing runtime: %w", err)
			}
			defer runtime.Close()

			err = validOperators.Init(operatorsParamsCollection)
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
				timeoutDuration = time.Duration(timeout) * time.Second
			}

			gadgetCtx := gadgetcontext.New(
				ctx,
				"",
				runtime,
				gadgetDesc,
				gadgetParams,
				operatorsParamCollection,
				parser,
				logger.DefaultLogger(),
				timeoutDuration,
			)

			outputModeInfo := strings.SplitN(outputMode, "=", 2)
			outputModeName := outputModeInfo[0]
			outputModeParams := ""
			if len(outputModeInfo) > 1 {
				outputModeParams = outputModeInfo[1]
			}

			if parser == nil {
				var transformResult func(result []byte) ([]byte, error)

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
					transformResult = func(result []byte) ([]byte, error) {
						return result, nil
					}
				}

				// This kind of gadgets return directly the result instead of
				// using the parser
				result, err := runtime.RunGadget(gadgetCtx)
				if err != nil {
					return fmt.Errorf("running gadget: %w", err)
				}

				transformed, err := transformResult(result)
				if err != nil {
					return fmt.Errorf("transforming result: %w", err)
				}

				fe.Output(string(transformed))

				return nil
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
			if outputModeParams != "" {
				valid, invalid := parser.VerifyColumnNames(strings.Split(outputModeParams, ","))

				for _, c := range invalid {
					log.Warnf("column %q not found", c)
				}

				if err := formatter.SetShowColumns(valid); err != nil {
					return err
				}
			}
			parser.SetLogCallback(fe.Logf)

			// Wire up callbacks before handing over to runtime depending on the output mode
			switch outputModeName {
			default:
				return fmt.Errorf("invalid output mode %q", outputModeName)
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
					fe.Clear()
					fe.Output(formatter.FormatHeader())
					break
				}
				fe.Output(formatter.FormatHeader())
				parser.SetEventCallback(formatter.EventHandlerFuncArray())
			case OutputModeJSON:
				parser.SetEventCallback(printEventAsJSONFn(fe))
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

	cmd.PersistentFlags().BoolVarP(
		&verbose,
		"verbose", "v",
		false,
		"Print debug information",
	)

	outputFormats.Append(gadgets.OutputFormats{
		"json": {
			Name:        "JSON",
			Description: "The output of the gadget is returned as raw JSON",
			Transform:   nil,
		},
	})
	defaultOutputFormat = "json"

	// Add parser output flags
	if parser != nil {
		of := gadgets.OutputFormat{
			Name:        "Columns",
			Description: "The output of the gadget is formatted in human readable columns.\n  You can optionally specify the columns to output using '-o columns=col1,col2,col3' etc.",
		}

		defaultOutputFormat = "columns=" + strings.Join(parser.GetDefaultColumns(), ",")

		var out strings.Builder
		fmt.Fprintf(&out, "\n    Available columns:\n")

		columnNamesAndDescriptions := parser.GetColumnNamesAndDescription()
		columnNames := make([]string, 0, len(columnNamesAndDescriptions))
		for columnName := range columnNamesAndDescriptions {
			columnNames = append(columnNames, columnName)
		}
		sort.Strings(columnNames)
		for _, columnName := range columnNames {
			description := columnNamesAndDescriptions[columnName]
			if description == "" {
				fmt.Fprintf(&out, "      %s\n", columnName)
				continue
			}
			fmt.Fprintf(&out, "      %s: %s\n", columnName, description)
		}

		of.Description += out.String()

		outputFormats.Append(gadgets.OutputFormats{OutputModeColumns: of})

		cmd.PersistentFlags().StringSliceVarP(
			&filters,
			"filter", "F",
			[]string{},
			`Filter rules
  A filter can match any column using the following syntax
    columnName:value       - matches, if the content of columnName equals exactly value
    columnName:!value      - matches, if the content of columnName does not equal exactly value
    columnName:>=value     - matches, if the content of columnName is greater or equal to the value
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

	// Add gadget flags
	addFlags(cmd, gadgetParams)

	// Add per-gadget operator flags
	for _, operatorParams := range operatorsParamCollection {
		addFlags(cmd, operatorParams)
	}
	return cmd
}

func addFlags(cmd *cobra.Command, params *params.Params) {
	defer func() {
		if err := recover(); err != nil {
			panic(fmt.Sprintf("registering params for command %q: %v", cmd.Use, err))
		}
	}()
	for _, p := range *params {
		desc := p.Description

		if p.PossibleValues != nil {
			desc += " [" + strings.Join(p.PossibleValues, ", ") + "]"
		}

		flag := cmd.PersistentFlags().VarPF(p, p.Key, p.Alias, desc)

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
			fe.Logf(logger.WarnLevel, "marshalling %+v: %s", ev, err)
			return
		}
		fe.Output(string(d))
	}
}
