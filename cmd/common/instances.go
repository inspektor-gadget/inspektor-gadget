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

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/ellipsis"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/formatter/textcolumns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
)

type GadgetInfo struct {
	pg *api.GadgetInstance
}

func AddInstanceCommands(
	rootCmd *cobra.Command,
	runtime *grpcruntime.Runtime,
) {
	runtimeParams := runtime.ParamDescs().ToParams()

	findGadgetInstance := func(idOrName string) (*api.GadgetInstance, error) {
		gadgetInstances, err := runtime.GetGadgetInstances(context.Background(), runtimeParams)
		if err != nil {
			return nil, err
		}
		var gadgetInstance *api.GadgetInstance
		for _, tmpGadgetInstance := range gadgetInstances {
			// Some heuristic to find the gadget the user requested

			// Check name match first
			if tmpGadgetInstance.Name == idOrName {
				gadgetInstance = tmpGadgetInstance
				break
			}

			// Check full match on ID
			if tmpGadgetInstance.Id == idOrName {
				gadgetInstance = tmpGadgetInstance
				break
			}

			if len(idOrName) < 32 {
				// allow partial matches
				if strings.HasPrefix(tmpGadgetInstance.Id, idOrName) {
					gadgetInstance = tmpGadgetInstance
					break
				}
			}
		}
		if gadgetInstance == nil {
			return nil, fmt.Errorf("not found")
		}
		return gadgetInstance, nil
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
			}, func(g *GadgetInfo) any {
				if g.pg == nil {
					return ""
				}
				return g.pg.Id[:12]
			})
			cols.MustAddColumn(columns.Attributes{
				Name:         "Name",
				Visible:      true,
				EllipsisType: ellipsis.End,
				Order:        20,
			}, func(g *GadgetInfo) any {
				if g.pg == nil {
					return ""
				}
				return g.pg.Name
			})
			cols.MustAddColumn(columns.Attributes{
				Name:         "Tags",
				Visible:      true,
				EllipsisType: ellipsis.End,
				Order:        30,
			}, func(g *GadgetInfo) any {
				if g.pg == nil {
					return ""
				}
				return strings.Join(g.pg.Tags, ",")
			})
			cols.MustAddColumn(columns.Attributes{
				Name:         "Gadget",
				Visible:      true,
				EllipsisType: ellipsis.End,
				Order:        50,
			}, func(g *GadgetInfo) any {
				if g.pg == nil {
					return ""
				}
				return g.pg.GadgetInfo.ImageName
			})
			// cols.MustAddColumn(columns.Attributes{
			// 	Name:         "Nodes",
			// 	Visible:      true,
			// 	EllipsisType: ellipsis.End,
			// 	Order:        60,
			// }, func(g *GadgetInfo) any {
			// 	return strings.Join(g.pg.GadgetInfo.Nodes, ",")
			// })

			formatter := textcolumns.NewFormatter(cols.GetColumnMap())
			fmt.Println(formatter.FormatHeader())

			gadgets, err := runtime.GetGadgetInstances(context.Background(), runtimeParams)
			if err != nil {
				return err
			}
			for _, gadget := range gadgets {
				gi := &GadgetInfo{pg: gadget}
				fmt.Println(formatter.FormatEntry(gi))
				if showDetails {
					for k, v := range gi.pg.GadgetInfo.ParamValues {
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
	AddFlags(listCmd, runtimeParams, nil, runtime)
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
			gadgetInstance, err := findGadgetInstance(gadgetInstanceID)
			if err != nil {
				return fmt.Errorf("finding gadget: %w", err)
			}

			return runtime.RemoveGadgetInstance(context.Background(), runtimeParams, gadgetInstance.Id)
		},
	}
	AddFlags(deleteCmd, runtimeParams, nil, runtime)
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
			gadgetInstance, err := findGadgetInstance(gadgetInstanceID)
			if err != nil {
				return fmt.Errorf("finding gadget: %w", err)
			}

			return runtime.StopGadgetInstance(context.Background(), runtimeParams, gadgetInstance.Id)
		},
	}
	AddFlags(stopCmd, runtimeParams, nil, runtime)
	rootCmd.AddCommand(stopCmd)
}
