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
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/frontends/console"
	cols "github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/runner"
)

const (
	OutputModeColumns    = "columns"
	OutputModeJSON       = "json"
	OutputModeJSONPretty = "jsonpretty"
	OutputModeYAML       = "yaml"
)

// AddCommandsFromRegistry adds all gadgets known by the registry as cobra commands as a subcommand to their categories
func AddCommandsFromRegistry(rootCmd *cobra.Command, runtime runtime.Runtime, runtimeGlobalParams *params.Params, columnFilters []cols.ColumnFilter) {
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
			columnFilters,
			runtime,
			runtimeGlobalParams,
			operatorsGlobalParamsCollection,
			gadgetInfo.OperatorParamsCollection.ToParams(),
		))
	}
}

func buildColumnsOutputFormat(gadgetParams *params.Params, parser parser.Parser) gadgets.OutputFormats {
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
	fmt.Fprintf(&out, "    Default columns: %s\n", strings.Join(parser.GetDefaultColumns(), ","))

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
	columnFilters []cols.ColumnFilter,
	runtime runtime.Runtime,
	runtimeGlobalParams *params.Params,
	operatorsGlobalParamsCollection params.Collection,
	operatorsParamsCollection params.Collection,
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
				if columnFilters != nil {
					parser.SetColumnFilters(columnFilters...)
				}

				outputFormats.Append(buildColumnsOutputFormat(gadgetParams, parser))
				outputFormatsHelp := buildOutputFormatsHelp(outputFormats)
				cmd.Flags().Lookup("output").Usage = strings.Join(outputFormatsHelp, "\n") + "\n\n"
				cmd.Flags().Lookup("output").DefValue = "columns"
			}

			if showHelp, _ := cmd.Flags().GetBool("help"); showHelp {
				return cmd.Help()
			}

			fe := console.NewFrontend()
			defer fe.Close()

			ctx := fe.GetContext()

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

			timeoutDuration := time.Duration(timeout) * time.Second

			outputModeInfo := strings.SplitN(outputMode, "=", 2)
			outputModeName := outputModeInfo[0]
			outputModeParams := ""
			if len(outputModeInfo) > 1 {
				outputModeParams = outputModeInfo[1]
			}

			return runner.PrepareAndRunGadget(
				ctx,
				"",
				runtime,
				runtimeParams,
				gadgetDesc,
				gadgetParams,
				args,
				validOperators,
				operatorsParamsCollection,
				parser,
				logger.DefaultLogger(),
				timeoutDuration,
				outputModeName,
				outputModeParams,
				fe,
				filters,
			)
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

	defaultOutputFormat = handleOutputFormats(outputFormats, gadgetDesc, gadgetParams, parser)

	_, hasCustomParser := gadgetDesc.(gadgets.GadgetDescCustomParser)

	if parser != nil || hasCustomParser {
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

func handleOutputFormats(outputFormats gadgets.OutputFormats, gadgetDesc gadgets.GadgetDesc, gadgetParams *params.Params, parser parser.Parser) string {
	var defaultOutputFormat string

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
		outputFormats.Append(buildColumnsOutputFormat(gadgetParams, parser))
	}
	_, hasCustomParser := gadgetDesc.(gadgets.GadgetDescCustomParser)

	if parser != nil || hasCustomParser {
		defaultOutputFormat = "columns"
	}

	// Add alternative output formats available in the gadgets
	if outputFormatInterface, ok := gadgetDesc.(gadgets.GadgetOutputFormats); ok {
		formats, defaultFormat := outputFormatInterface.OutputFormats()
		outputFormats.Append(formats)
		defaultOutputFormat = defaultFormat
	}

	return defaultOutputFormat
}
