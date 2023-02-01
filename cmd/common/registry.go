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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/frontends/console"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/internal/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/internal/logger"
	"github.com/inspektor-gadget/inspektor-gadget/internal/operators"
	"github.com/inspektor-gadget/inspektor-gadget/internal/parser"
	"github.com/inspektor-gadget/inspektor-gadget/internal/runtime"
	cols "github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

// AddCommandsFromRegistry adds all gadgets known by the registry as cobra commands as a subcommand to their categories
func AddCommandsFromRegistry(rootCmd *cobra.Command, runtime runtime.Runtime, columnFilters []cols.ColumnFilter) {
	runtimeParams := runtime.GlobalParamDescs().ToParams()

	// Build lookup
	lookup := make(map[string]*cobra.Command)
	for _, cmd := range rootCmd.Commands() {
		lookup[cmd.Name()] = cmd
	}

	// Add runtime flags
	addFlags(rootCmd, runtimeParams)

	// Add operator global flags
	operatorsParamsCollection := operators.GlobalParamsCollection()
	for _, operatorParams := range operatorsParamsCollection {
		addFlags(rootCmd, operatorParams)
	}

	// Add all known gadgets to cobra in their respective categories
	categories := gadgets.GetCategories()
	for _, gadget := range gadgetregistry.GetGadgets() {
		cmd, ok := lookup[gadget.Category()]
		if !ok {
			// Category not found, add it
			categoryDescription, ok := categories[gadget.Category()]
			if !ok {
				panic(fmt.Errorf("category unknown: %q", gadget.Category()))
			}
			cmd = &cobra.Command{
				Use:   gadget.Category(),
				Short: categoryDescription,
			}
			rootCmd.AddCommand(cmd)
			lookup[gadget.Category()] = cmd
		}
		cmd.AddCommand(buildCommandFromGadget(gadget, columnFilters, runtime, runtimeParams, operatorsParamsCollection))
	}
}

func buildGadgetDoc(gadget gadgets.Gadget, parser parser.Parser) string {
	var out strings.Builder
	out.WriteString(gadget.Description() + "\n\n")

	if parser != nil {
		out.WriteString("Available columns:\n")
		for columnName, description := range parser.GetColumnNamesAndDescription() {
			out.WriteString("\t" + columnName + "\n")
			if description != "" {
				out.WriteString("\t  " + description + "\n")
			}
		}
	}
	return out.String()
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
	outputFormatsHelp = append([]string{fmt.Sprintf("Output format (%s).", strings.Join(supportedOutputFormats, ", ")), ""}, outputFormatsHelp...)
	return outputFormatsHelp
}

func buildCommandFromGadget(gadget gadgets.Gadget,
	columnFilters []cols.ColumnFilter,
	runtime runtime.Runtime,
	runtimeParams *params.Params,
	operatorsParamsCollection params.Collection,
) *cobra.Command {
	var outputMode string
	var verbose bool
	var showColumns []string
	var filters []string
	var timeout int

	outputFormats := gadgets.OutputFormats{}
	defaultOutputFormat := ""

	// Instantiate parser - this is important to do, because we might apply filters and such to this instance
	parser := gadget.Parser()
	if parser != nil && columnFilters != nil {
		parser.SetColumnFilters(columnFilters...)
	}

	// Instantiate gadget params - this is important, because the params get filled out by cobra
	gadgetParams := gadget.ParamDescs().ToParams()

	// Get per gadget operator params
	validOperators := operators.GetOperatorsForGadget(gadget)
	operatorsPerGadgetParamCollection := validOperators.PerGadgetParamCollection()

	cmd := &cobra.Command{
		Use:          gadget.Name(),
		Short:        gadget.Description(),
		Long:         buildGadgetDoc(gadget, parser),
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

			fe := console.NewFrontend()
			defer fe.Close()

			ctx := fe.GetContext()

			// Handle timeout parameter by adding a timeout to the context
			if timeout != 0 {
				tmpCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
				defer cancel()
				ctx = tmpCtx
			}

			log := logger.DefaultLogger()

			gadgetContext := gadgetcontext.New(
				ctx,
				"",
				runtime,
				gadget,
				gadgetParams,
				parser,
				log,
			)

			if parser == nil {
				// This kind of gadgets return directly the result instead of
				// using the parser
				result, err := runtime.RunGadget(gadgetContext, operatorsPerGadgetParamCollection)
				if err != nil {
					return fmt.Errorf("running gadget: %w", err)
				}

				switch outputMode {
				default:
					transformer, ok := gadget.(gadgets.GadgetOutputFormats)
					if !ok {
						return fmt.Errorf("gadget does not provide any output formats")
					}
					formats, defaultFormat := transformer.OutputFormats()
					transformed, err := formats[defaultFormat].Transform(result)
					if err != nil {
						return fmt.Errorf("transforming gadget result: %w", err)
					}
					fe.Output(string(transformed))
				case utils.OutputModeJSON:
					fe.Output(string(result))
				}

				return nil
			}

			// Add some custom params like filters that are available when using parser
			if len(filters) > 0 {
				err = parser.SetFilters(filters)
				if err != nil {
					return err // TODO: Wrap
				}
				gadgetParams.AddKeyValuePair("columns_filters", strings.Join(filters, ",")) // TODO: maybe encode?! difficult for CRs though
			}

			if gadget.Type().CanSort() {
				sortBy := gadgetParams.Get(gadgets.ParamSortBy).AsStringSlice()
				err := parser.SetSorting(sortBy)
				if err != nil {
					return err // TODO: Wrap
				}
			}

			formatter := parser.GetTextColumnsFormatter()
			formatter.SetShowColumns(showColumns)
			parser.SetErrorCallback(fe.Error)

			// Wire up callbacks before handing over to runtime depending on the output mode
			switch outputMode {
			default:
				formatter.SetEventCallback(fe.Output)

				// Enable additional output, if the gadget supports it (e.g. profile/cpu)
				//  TODO: This can be optimized later on
				formatter.SetEnableExtraLines(true)

				parser.SetEventCallback(formatter.EventHandlerFunc())
				if gadget.Type().IsPeriodic() {
					// In case of periodic outputting gadgets, this is done as full table output, and we need to
					// clear the screen for every interval, that's why we add fe.Clear here
					parser.SetEventCallback(formatter.EventHandlerFuncArray(
						fe.Clear,
						func() {
							fe.Output(formatter.FormatHeader())
						},
					))
					break
				}
				fe.Output(formatter.FormatHeader())
				parser.SetEventCallback(formatter.EventHandlerFuncArray())
			case utils.OutputModeJSON:
				parser.SetEventCallback(printEventAsJSON)
			}

			// Gadgets with parser don't return anything, they provide the
			// output via the parser
			_, err = runtime.RunGadget(gadgetContext, operatorsPerGadgetParamCollection)
			if err != nil {
				return fmt.Errorf("running gadget: %w", err)
			}

			return nil
		},
	}

	if gadget.Type() != gadgets.TypeOneShot {
		// Add timeout
		cmd.PersistentFlags().IntVarP(&timeout, "timeout", "t", 0, "Number of seconds that the gadget will run for, 0 to disable")
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
		outputFormats.Append(gadgets.OutputFormats{
			"columns": {
				Name:        "Columns",
				Description: "The output of the gadget is formatted in human readable columns",
			},
		})
		defaultOutputFormat = "columns"

		cmd.PersistentFlags().StringSliceVarP(
			&showColumns,
			"columns", "C",
			parser.GetDefaultColumns(),
			"Columns to output",
		)
		cmd.PersistentFlags().StringSliceVarP(
			&filters,
			"filter", "F",
			[]string{},
			"Filter rules",
		)
	}

	// Add alternative output formats available in the gadgets
	if outputFormatInterface, ok := gadget.(gadgets.GadgetOutputFormats); ok {
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
	gadgetParams.Add(*gadgets.GadgetParams(gadget, parser).ToParams()...)

	// Add gadget flags
	addFlags(cmd, gadgetParams)

	// Add per-gadget operator flags
	for _, operatorParams := range operatorsPerGadgetParamCollection {
		addFlags(cmd, operatorParams)
	}
	return cmd
}

func addFlags(cmd *cobra.Command, params *params.Params) {
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

func printEventAsJSON(ev any) {
	d, err := json.Marshal(ev)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshalling %+v: %v", ev, err)
		return
	}
	fmt.Fprintln(os.Stdout, string(d))
}
