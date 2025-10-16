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
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/ellipsis"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/formatter/textcolumns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
)

type GadgetInfo struct {
	pg *api.GadgetInstance
}

type NodeInstanceState struct {
	Node    string `yaml:"Node"`
	Status  string `yaml:"Status"`
	Message string `yaml:"Message"`
}

type InstanceState struct {
	ID            string              `yaml:"ID"`
	Name          string              `yaml:"Name"`
	Image         string              `yaml:"Image"`
	TimeCreated   string              `yaml:"TimeCreated"`
	Params        map[string]string   `yaml:"Params"`
	NodeInstances []NodeInstanceState `yaml:"NodeInstances"`
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
				Order:        40,
			}, func(g *GadgetInfo) any {
				if g.pg == nil {
					return ""
				}
				return g.pg.GadgetConfig.ImageName
			})
			cols.MustAddColumn(columns.Attributes{
				Name:         "Status",
				Visible:      true,
				EllipsisType: ellipsis.End,
				Order:        50,
			}, func(g *GadgetInfo) any {
				if g.pg == nil || g.pg.State == nil {
					return ""
				}
				return toInstanceStatus(g.pg.State)
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

	showCmd := &cobra.Command{
		Use:          "show",
		Aliases:      []string{"s", "sh"},
		Short:        "Show details of a gadget instance",
		SilenceUsage: true,
		Args:         cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			instances, ambiguous, notfound, err := findGadgetInstances(runtime, runtimeParams, args)
			if err != nil {
				return fmt.Errorf("getting gadget instances: %w", err)
			}
			if len(ambiguous) > 0 {
				return fmt.Errorf("ambiguous names/ids: %s", strings.Join(ambiguous, ", "))
			}
			if len(notfound) > 0 {
				return fmt.Errorf("instance %q not found", args[0])
			}
			nStates, err := runtime.GetNodeInstanceStates(context.Background(), runtimeParams, instances[0].Id)
			if err != nil {
				return fmt.Errorf("getting node instances state: %w", err)
			}

			var nodeInstances []NodeInstanceState
			for _, ni := range nStates {
				nodeInstances = append(nodeInstances, NodeInstanceState{
					Node:    ni.Node,
					Status:  toInstanceStatus(ni.State),
					Message: ni.State.Message,
				})
			}
			state := InstanceState{
				ID:            instances[0].Id,
				Name:          instances[0].Name,
				Image:         instances[0].GadgetConfig.ImageName,
				TimeCreated:   time.Unix(instances[0].TimeCreated, 0).Format(time.RFC3339),
				Params:        instances[0].GadgetConfig.ParamValues,
				NodeInstances: nodeInstances,
			}

			out, err := yaml.Marshal(state)
			if err != nil {
				return fmt.Errorf("marshalling state to YAML: %w", err)
			}
			fmt.Print(string(out))

			return nil
		},
	}
	AddFlags(showCmd, runtimeParams, nil, runtime)
	rootCmd.AddCommand(showCmd)
}

func toInstanceStatus(state *api.GadgetInstanceState) string {
	if state == nil {
		return ""
	}
	switch state.Status {
	case api.GadgetInstanceStatus_StatusRunning:
		return "Running"
	case api.GadgetInstanceStatus_StatusError:
		return "Error"
	default:
		return "Unknown"
	}
}
