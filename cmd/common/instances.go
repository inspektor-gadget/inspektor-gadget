// Copyright 2023-2024 The Inspektor Gadget authors
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
	"os"
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

	listCmd := &cobra.Command{
		Use:          "list",
		Aliases:      []string{"l", "ls", "ps"},
		Short:        "List gadget instances",
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
				return g.pg.GadgetConfig.ImageName
			})

			formatter := textcolumns.NewFormatter(cols.GetColumnMap())
			fmt.Println(formatter.FormatHeader())

			gadgets, err := runtime.GetGadgetInstances(context.Background(), runtimeParams)
			if err != nil {
				return err
			}
			for _, gadget := range gadgets {
				gi := &GadgetInfo{pg: gadget}
				fmt.Println(formatter.FormatEntry(gi))
			}
			return nil
		},
	}
	AddFlags(listCmd, runtimeParams, nil, runtime)
	rootCmd.AddCommand(listCmd)

	deleteCmd := &cobra.Command{
		Use:          "delete",
		Aliases:      []string{"d", "del"},
		Short:        "Delete one or more gadget instances",
		SilenceUsage: true,
		Args:         cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			instances, ambiguous, notfound, err := findGadgetInstances(runtime, runtimeParams, args)
			if err != nil {
				return fmt.Errorf("getting gadget instances: %w", err)
			}
			if len(ambiguous) > 0 {
				fmt.Fprintf(os.Stderr, "ambiguous names/ids: %s\n", strings.Join(ambiguous, ", "))
			}
			if len(notfound) > 0 {
				fmt.Fprintf(os.Stderr, "not found names/ids: %s\n", strings.Join(notfound, ", "))
			}
			for _, instance := range instances {
				err := runtime.RemoveGadgetInstance(context.Background(), runtimeParams, instance.Id)
				if err != nil {
					fmt.Fprintf(os.Stderr, "failed to remove gadget instance %q: %v\n", instance.Id, err)
				}
				fmt.Printf("%s\n", instance.Id)
			}
			return nil
		},
	}
	AddFlags(deleteCmd, runtimeParams, nil, runtime)
	rootCmd.AddCommand(deleteCmd)
}
