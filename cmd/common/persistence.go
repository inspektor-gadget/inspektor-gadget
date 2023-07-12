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

package common

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/frontends/console"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/ellipsis"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/formatter/textcolumns"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/runner"
)

type GadgetInfo struct {
	pg *api.PersistentGadget
}

func AddPersistenceCommands(
	rootCmd *cobra.Command,
	runtime *grpcruntime.Runtime,
	runtimeGlobalParams *params.Params,
	columnFilters []columns.ColumnFilter,
) {
	runtimeParams := runtime.ParamDescs().ToParams()

	findGadgetInstance := func(idOrName string) (*api.PersistentGadget, error) {
		persistentGadgets, err := runtime.GetPersistentGadgets(context.Background(), runtimeParams)
		if err != nil {
			return nil, err
		}
		var persistentGadget *api.PersistentGadget
		for _, tmpPersistentGadget := range persistentGadgets {
			// Some heuristic to find the gadget the user requested

			// Check name match first
			if tmpPersistentGadget.Name == idOrName {
				persistentGadget = tmpPersistentGadget
				break
			}

			// Check full match on ID
			if tmpPersistentGadget.Id == idOrName {
				persistentGadget = tmpPersistentGadget
				break
			}

			if len(idOrName) < 32 {
				// allow partial matches
				if strings.HasPrefix(tmpPersistentGadget.Id, idOrName) {
					persistentGadget = tmpPersistentGadget
					break
				}
			}
		}
		if persistentGadget == nil {
			return nil, fmt.Errorf("not found")
		}
		return persistentGadget, nil
	}

	var showDetails bool
	listCmd := &cobra.Command{
		Use:          "list",
		Aliases:      []string{"l"},
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cols := columns.MustCreateColumns[GadgetInfo]()
			cols.MustAddColumn(columns.Attributes{
				Name:         "ID",
				Visible:      true,
				EllipsisType: ellipsis.End,
				Order:        10,
				Width:        12,
				MaxWidth:     12,
				MinWidth:     12,
			}, func(g *GadgetInfo) string {
				return g.pg.Id[:12]
			})
			cols.MustAddColumn(columns.Attributes{
				Name:         "Name",
				Visible:      true,
				EllipsisType: ellipsis.End,
				Order:        20,
			}, func(g *GadgetInfo) string {
				return g.pg.Name
			})
			cols.MustAddColumn(columns.Attributes{
				Name:         "Tags",
				Visible:      true,
				EllipsisType: ellipsis.End,
				Order:        30,
			}, func(g *GadgetInfo) string {
				return strings.Join(g.pg.Tags, ",")
			})
			cols.MustAddColumn(columns.Attributes{
				Name:         "Gadget",
				Visible:      true,
				EllipsisType: ellipsis.End,
				Order:        50,
			}, func(g *GadgetInfo) string {
				return fmt.Sprintf("builtin://%s/%s", g.pg.GadgetInfo.GadgetCategory, g.pg.GadgetInfo.GadgetName)
			})
			cols.MustAddColumn(columns.Attributes{
				Name:         "Nodes",
				Visible:      true,
				EllipsisType: ellipsis.End,
				Order:        60,
			}, func(g *GadgetInfo) string {
				return strings.Join(g.pg.GadgetInfo.Nodes, ",")
			})

			formatter := textcolumns.NewFormatter(cols.GetColumnMap())
			fmt.Println(formatter.FormatHeader())

			gadgets, err := runtime.GetPersistentGadgets(context.Background(), runtimeParams)
			if err != nil {
				return err
			}
			for _, gadget := range gadgets {
				gi := &GadgetInfo{pg: gadget}
				fmt.Println(formatter.FormatEntry(gi))
				if showDetails {
					for k, v := range gi.pg.GadgetInfo.Params {
						if len(v) > 128 {
							v = v[:128] + "…"
						}
						fmt.Printf("  %-32s %s\n", k, v)
					}
				}
			}
			return nil
		},
	}
	listCmd.PersistentFlags().BoolVarP(&showDetails, "details", "", false, "show details")
	addFlags(listCmd, runtimeParams, nil, runtime)
	rootCmd.AddCommand(listCmd)

	deleteCmd := &cobra.Command{
		Use:          "delete",
		Aliases:      []string{"d"},
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("missing id")
			}

			gadgetInstanceID := args[0]
			persistentGadget, err := findGadgetInstance(gadgetInstanceID)
			if err != nil {
				return fmt.Errorf("finding gadget: %w", err)
			}

			return runtime.RemovePersistentGadget(context.Background(), runtimeParams, persistentGadget.Id)
		},
	}
	addFlags(deleteCmd, runtimeParams, nil, runtime)
	rootCmd.AddCommand(deleteCmd)

	stopCmd := &cobra.Command{
		Use:          "stop",
		Aliases:      []string{"s"},
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("missing id")
			}

			gadgetInstanceID := args[0]
			persistentGadget, err := findGadgetInstance(gadgetInstanceID)
			if err != nil {
				return fmt.Errorf("finding gadget: %w", err)
			}

			return runtime.StopPersistentGadget(context.Background(), runtimeParams, persistentGadget.Id)
		},
	}
	addFlags(stopCmd, runtimeParams, nil, runtime)
	rootCmd.AddCommand(stopCmd)

	attachCmd := &cobra.Command{
		Use:                "attach",
		Aliases:            []string{"a"},
		DisableFlagParsing: true,
		SilenceUsage:       true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Since flags are not parsed, yet, we need to find the ID manually
			if len(args) == 0 {
				return fmt.Errorf("missing id")
			}

			gadgetInstanceID := args[0]

			persistentGadget, err := findGadgetInstance(gadgetInstanceID)
			if err != nil {
				return fmt.Errorf("finding gadget: %w", err)
			}
			if persistentGadget == nil {
				return fmt.Errorf("gadget instance %q not found", gadgetInstanceID)
			}

			// Prepare a lightweight version from the persistent gadget information

			// Lookup gadget desc
			gadgetDesc := gadgetregistry.Get(persistentGadget.GadgetInfo.GadgetCategory,
				persistentGadget.GadgetInfo.GadgetName)
			if gadgetDesc == nil {
				return fmt.Errorf("gadget not supported")
			}

			// Instantiate parser - this is important to do, because we might apply filters and such to this instance
			parser := gadgetDesc.Parser()
			if parser != nil && columnFilters != nil {
				parser.SetColumnFilters(columnFilters...)
			}

			gadgetParams := gadgetDesc.ParamDescs().ToParams()

			// Add params matching the gadget type
			gadgetParams.Add(*gadgets.GadgetParams(gadgetDesc, parser).ToParams()...)

			validOperators := operators.GetOperatorsForGadget(gadgetDesc)
			operatorParamCollection := validOperators.ParamCollection()

			err = gadgets.ParamsFromMap(
				persistentGadget.GadgetInfo.Params,
				gadgetParams,
				runtimeParams,
				operatorParamCollection,
			)
			if err != nil {
				return err
			}

			// manually remove persistent flag, otherwise this would spawn another instance
			runtimeParams.Set(grpcruntime.ParamDetach, "false")

			var outputMode string
			outputFormats := gadgets.OutputFormats{}
			defaultOutputFormat := handleOutputFormats(outputFormats, gadgetDesc, gadgetParams, parser)

			outputFormatsHelp := buildOutputFormatsHelp(outputFormats)

			cmd.PersistentFlags().StringVarP(
				&outputMode,
				"output",
				"o",
				defaultOutputFormat,
				strings.Join(outputFormatsHelp, "\n")+"\n\n",
			)

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
				cmd.PersistentFlags().Lookup("output").Usage = strings.Join(outputFormatsHelp, "\n") + "\n\n"
				cmd.PersistentFlags().Lookup("output").DefValue = "columns"
			}

			cmd.DisableFlagParsing = false
			err = cmd.ParseFlags(args)
			if err != nil {
				return err
			}

			if showHelp, _ := cmd.Flags().GetBool("help"); showHelp {
				return cmd.Help()
			}

			outputModeInfo := strings.SplitN(outputMode, "=", 2)
			outputModeName := outputModeInfo[0]
			outputModeParams := ""
			if len(outputModeInfo) > 1 {
				outputModeParams = outputModeInfo[1]
			}

			err = runtime.Init(runtimeGlobalParams)
			if err != nil {
				return fmt.Errorf("initializing runtime: %w", err)
			}
			defer runtime.Close()

			err = validOperators.Init(operators.GlobalParamsCollection())
			if err != nil {
				return fmt.Errorf("initializing operators: %w", err)
			}
			defer validOperators.Close()

			fe := console.NewFrontend()
			defer fe.Close()

			ctx := fe.GetContext()

			return runner.PrepareAndRunGadget(
				ctx,
				persistentGadget.Id,
				runtime,
				runtimeParams,
				gadgetDesc,
				gadgetParams,
				cmd.Flags().Args(),
				validOperators,
				operatorParamCollection,
				parser,
				logger.DefaultLogger(),
				0,
				outputModeName,
				outputModeParams,
				fe,
				[]string{}, // TODO: should we implement local filtering as well?
			)
		},
	}
	addFlags(attachCmd, runtimeParams, nil, runtime)
	rootCmd.AddCommand(attachCmd)
}
