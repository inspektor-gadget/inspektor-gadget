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

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/local-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/traceloop/tracer"
	"github.com/spf13/cobra"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	traceloopTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/traceloop/types"
	localgadgetmanager "github.com/inspektor-gadget/inspektor-gadget/pkg/local-gadget-manager"
)

func newTraceloopCmd() *cobra.Command {
	var commonFlags utils.CommonFlags

	cmd := &cobra.Command{
		Use:   "traceloop",
		Short: "Get strace-like logs of a container from the past",
		RunE: func(cmd *cobra.Command, args []string) error {
			localGadgetManager, err := localgadgetmanager.NewManager(commonFlags.RuntimeConfigs)
			if err != nil {
				return fmt.Errorf("error creating local gadget manager: %w", commonutils.WrapInErrManagerInit(err))
			}
			defer localGadgetManager.Close()

			tracer, err := tracer.NewTracer(&localGadgetManager.ContainerCollection)
			if err != nil {
				return fmt.Errorf("error creating tracer: %w", err)
			}
			defer tracer.Stop()

			containers := localGadgetManager.GetContainersBySelector(&containercollection.ContainerSelector{
				Name: commonFlags.Containername,
			})
			if len(containers) == 0 {
				return fmt.Errorf("no container for name %q", commonFlags.Containername)
			}

			for _, container := range containers {
				err := tracer.Attach(container.ID, container.Mntns)
				if err != nil {
					return err
				}
			}

			columns := traceloopTypes.GetColumns()
			if len(containers) > 1 {
				column, ok := columns.GetColumn("container")
				if !ok {
					return errors.New("no column named container")
				}
				column.Visible = true
			}

			parser, err := commonutils.NewGadgetParserWithRuntimeInfo(&commonFlags.OutputConfig, columns)
			if err != nil {
				return err
			}

			if commonFlags.OutputMode != commonutils.OutputModeJSON {
				fmt.Println("Tracing syscalls... Hit Ctrl-C to end")
			}

			exit := make(chan os.Signal, 1)
			signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)

			<-exit

			// Just to avoid mixing Ctrl^C and data.
			fmt.Println()

			if commonFlags.OutputMode != commonutils.OutputModeJSON {
				fmt.Println(parser.BuildColumnsHeader())
			}

			for _, container := range containers {
				events, err := tracer.Read(container.ID)
				if err != nil {
					return err
				}

				for _, event := range events {
					var line string

					if commonFlags.OutputMode == commonutils.OutputModeJSON {
						b, err := json.Marshal(event)
						if err != nil {
							return commonutils.WrapInErrMarshalOutput(err)
						}

						line = string(b)
					} else {
						line = parser.TransformIntoColumns(event)
					}

					fmt.Println(line)
				}
			}

			return nil
		},
	}

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}
