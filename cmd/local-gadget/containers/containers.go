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
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/local-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	localgadgetmanager "github.com/inspektor-gadget/inspektor-gadget/pkg/local-gadget-manager"
)

const localGadgetSubKey = "local-gadget-key"

func NewListContainersCmd() *cobra.Command {
	var commonFlags utils.CommonFlags
	var optionWatch bool

	cmd := &cobra.Command{
		Use:   "list-containers",
		Short: "List all containers",
		RunE: func(*cobra.Command, []string) error {
			localGadgetManager, err := localgadgetmanager.NewManager(commonFlags.RuntimeConfigs)
			if err != nil {
				return commonutils.WrapInErrManagerInit(err)
			}
			defer localGadgetManager.Close()

			selector := containercollection.ContainerSelector{
				Name: commonFlags.Containername,
			}

			if !optionWatch {
				parser, err := commonutils.NewGadgetParserWithRuntimeInfo(&commonFlags.OutputConfig, containercollection.GetColumns())
				if err != nil {
					return commonutils.WrapInErrParserCreate(err)
				}
				containers := localGadgetManager.GetContainersBySelector(&selector)

				parser.Sort(containers, []string{"runtime", "name"})
				if err = printContainers(parser, commonFlags, containers); err != nil {
					return err
				}
				return nil
			}

			cols := columns.MustCreateColumns[containercollection.PubSubEvent]()
			cols.SetExtractor("event", func(event *containercollection.PubSubEvent) string {
				return event.Type.String()
			})

			parser, err := commonutils.NewGadgetParserWithRuntimeInfo(&commonFlags.OutputConfig, cols)
			if err != nil {
				return commonutils.WrapInErrParserCreate(err)
			}
			containers := localGadgetManager.ContainerCollection.Subscribe(
				localGadgetSubKey,
				selector,
				func(event containercollection.PubSubEvent) {
					if err = printPubSubEvent(parser, commonFlags, &event); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: %s\n", err)
					}
				},
			)
			defer localGadgetManager.ContainerCollection.Unsubscribe(localGadgetSubKey)

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

			stop := make(chan os.Signal, 1)
			signal.Notify(stop, syscall.SIGINT)
			<-stop

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
	case commonutils.OutputModeCustomColumns:
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
	case commonutils.OutputModeCustomColumns:
		fmt.Println(parser.TransformIntoColumns(event))
	}

	return nil
}
