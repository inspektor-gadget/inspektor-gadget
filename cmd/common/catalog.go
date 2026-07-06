// Copyright 2026 The Inspektor Gadget authors
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

type catalogGadget struct {
	cg *api.CatalogGadget
}

// AddCatalogCommands adds the `catalog` command group, which lets clients
// discover the server-side curated list of gadgets. It is discovery-only; use
// the regular run/attach commands to actually run a gadget.
func AddCatalogCommands(
	rootCmd *cobra.Command,
	runtime *grpcruntime.Runtime,
) {
	runtimeParams := runtime.ParamDescs().ToParams()

	catalogCmd := &cobra.Command{
		Use:          "catalog",
		Short:        "Manage the server-side gadget catalog",
		SilenceUsage: true,
	}

	var tags []string

	listCmd := &cobra.Command{
		Use:          "list",
		Aliases:      []string{"l", "ls"},
		Short:        "List gadgets available in the catalog",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cols := columns.MustCreateColumns[catalogGadget]()
			cols.MustAddColumn(columns.Attributes{
				Name:         "Name",
				Visible:      true,
				EllipsisType: ellipsis.End,
				Order:        10,
			}, func(g *catalogGadget) any {
				if g.cg == nil {
					return ""
				}
				return g.cg.Name
			})
			cols.MustAddColumn(columns.Attributes{
				Name:         "Image",
				Visible:      true,
				EllipsisType: ellipsis.Start,
				Order:        20,
			}, func(g *catalogGadget) any {
				if g.cg == nil {
					return ""
				}
				return g.cg.Image
			})
			cols.MustAddColumn(columns.Attributes{
				Name:         "Tags",
				Visible:      true,
				EllipsisType: ellipsis.End,
				Order:        30,
			}, func(g *catalogGadget) any {
				if g.cg == nil {
					return ""
				}
				return strings.Join(g.cg.Tags, ",")
			})
			cols.MustAddColumn(columns.Attributes{
				Name:         "Description",
				Visible:      true,
				EllipsisType: ellipsis.End,
				Order:        40,
			}, func(g *catalogGadget) any {
				if g.cg == nil {
					return ""
				}
				return g.cg.Description
			})

			gadgets, err := runtime.GetCatalog(context.Background(), runtimeParams)
			if err != nil {
				return err
			}

			gadgets = filterCatalogByTags(gadgets, tags)

			formatter := textcolumns.NewFormatter(cols.GetColumnMap())
			fmt.Println(formatter.FormatHeader())
			for _, gadget := range gadgets {
				fmt.Println(formatter.FormatEntry(&catalogGadget{cg: gadget}))
			}
			return nil
		},
	}
	listCmd.Flags().StringSliceVar(&tags, "tags", nil,
		"Only show gadgets that have all of the given tags (comma-separated)")
	AddFlags(listCmd, runtimeParams, nil, runtime)
	catalogCmd.AddCommand(listCmd)

	rootCmd.AddCommand(catalogCmd)
}

// filterCatalogByTags returns the gadgets that contain all of the requested
// tags. When no tags are requested, all gadgets are returned.
func filterCatalogByTags(gadgets []*api.CatalogGadget, tags []string) []*api.CatalogGadget {
	if len(tags) == 0 {
		return gadgets
	}

	filtered := make([]*api.CatalogGadget, 0, len(gadgets))
	for _, gadget := range gadgets {
		if hasAllTags(gadget.Tags, tags) {
			filtered = append(filtered, gadget)
		}
	}
	return filtered
}

func hasAllTags(gadgetTags, wantTags []string) bool {
	for _, want := range wantTags {
		found := false
		for _, have := range gadgetTags {
			if have == want {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
