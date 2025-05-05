// Copyright 2022 The Inspektor Gadget authors
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

package containers

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/moby/moby/pkg/stringid"
	"github.com/spf13/cobra"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/ig/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	igmanager "github.com/inspektor-gadget/inspektor-gadget/pkg/ig-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

const igSubKey = "ig-key"

func NewListContainersCmd() *cobra.Command {
	var commonFlags utils.CommonFlags
	var optionWatch bool

	cmd := &cobra.Command{
		Use:   "list-containers",
		Short: "List all containers",
		RunE: func(*cobra.Command, []string) error {
			// The list-containers command is not a gadget, so the local
			// runtime won't call host.Init().
			err := host.Init(host.Config{})
			if err != nil {
				return err
			}

			igmanager, err := igmanager.NewManager(commonFlags.RuntimeConfigs, nil)
			if err != nil {
				return commonutils.WrapInErrManagerInit(err)
			}
			defer igmanager.Close()

			selector := containercollection.ContainerSelector{
				Runtime: containercollection.RuntimeSelector{
					ContainerName: commonFlags.Containername,
				},
			}

			if !optionWatch {
				parser, err := commonutils.NewGadgetParserWithK8sAndRuntimeInfo(&commonFlags.OutputConfig, columnsWithAdjustedVisibility(containercollection.GetColumns()))
				if err != nil {
					return commonutils.WrapInErrParserCreate(err)
				}
				containers := igmanager.GetContainersBySelector(&selector)

				parser.Sort(containers, []string{"runtime.runtimeName", "runtime.containerName"})
				if err = printContainers(parser, commonFlags, containers); err != nil {
					return err
				}
				return nil
			}

			cols := columnsWithAdjustedVisibility(columns.MustCreateColumns[containercollection.PubSubEvent]())
			cols.SetExtractor("event", func(event *containercollection.PubSubEvent) any {
				return event.Type.String()
			})
			cols.MustSetExtractor("runtime.containerImageName", func(event *containercollection.PubSubEvent) any {
				if event == nil || event.Container == nil {
					return ""
				}
				if strings.Contains(event.Container.Runtime.ContainerImageName, "sha256") {
					return stringid.TruncateID(event.Container.Runtime.ContainerImageName)
				}
				return event.Container.Runtime.ContainerImageName
			})

			parser, err := commonutils.NewGadgetParserWithK8sAndRuntimeInfo(&commonFlags.OutputConfig, cols)
			if err != nil {
				return commonutils.WrapInErrParserCreate(err)
			}
			containers := igmanager.Subscribe(
				igSubKey,
				selector,
				func(event containercollection.PubSubEvent) {
					if err = printPubSubEvent(parser, commonFlags, &event); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: %s\n", err)
					}
				},
			)
			defer igmanager.Unsubscribe(igSubKey)

			if commonFlags.OutputMode != commonutils.OutputModeJSON {
				fmt.Println(parser.BuildColumnsHeader())
			}
			timestamp := time.Now().Format(time.RFC3339)
			for _, container := range containers {
				e := containercollection.PubSubEvent{
					Timestamp: timestamp,
					Type:      containercollection.EventTypeAddContainer,
					Container: container,
				}
				if err = printPubSubEvent(parser, commonFlags, &e); err != nil {
					return err
				}
			}

			utils.WaitForEnd(&commonFlags)
			return nil
		},
	}

	cmd.Flags().BoolVarP(
		&optionWatch,
		"watch", "w",
		false,
		"After listing the containers, watch for new containers")

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}

func printContainers(parser *commonutils.GadgetParser[containercollection.Container], commonFlags utils.CommonFlags, containers []*containercollection.Container) error {
	switch commonFlags.OutputMode {
	case commonutils.OutputModeJSON:
		b, err := json.MarshalIndent(containers, "", "  ")
		if err != nil {
			return commonutils.WrapInErrMarshalOutput(err)
		}

		fmt.Printf("%s\n", b)
	case commonutils.OutputModeColumns:
		fmt.Println(parser.TransformIntoTable(containers))
	}

	return nil
}

func printPubSubEvent(parser *commonutils.GadgetParser[containercollection.PubSubEvent], commonFlags utils.CommonFlags, event *containercollection.PubSubEvent) error {
	switch commonFlags.OutputMode {
	case commonutils.OutputModeJSON:
		b, err := json.MarshalIndent(event, "", "  ")
		if err != nil {
			return commonutils.WrapInErrMarshalOutput(err)
		}
		fmt.Printf("%s\n", b)
	case commonutils.OutputModeColumns:
		fmt.Println(parser.TransformIntoColumns(event))
	}

	return nil
}

func columnsWithAdjustedVisibility[T containercollection.Container | containercollection.PubSubEvent](cols *columns.Columns[T]) *columns.Columns[T] {
	for _, c := range cols.GetColumnMap(columns.WithTag("kubernetes")) {
		c.Visible = false
	}
	for _, c := range cols.GetColumnMap(columns.WithTag("runtime")) {
		c.Visible = true
	}
	return cols
}
