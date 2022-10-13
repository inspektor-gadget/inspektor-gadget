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
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/local-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/traceloop/tracer"
	"github.com/spf13/cobra"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	localgadgetmanager "github.com/inspektor-gadget/inspektor-gadget/pkg/local-gadget-manager"
)

func newTraceloopCmd() *cobra.Command {
	var commonFlags utils.CommonFlags

	cmd := &cobra.Command{
		Use:   "traceloop",
		Short: "Get strace-like logs of a pod from the past",
		RunE: func(cmd *cobra.Command, args []string) error {
			localGadgetManager, err := localgadgetmanager.NewManager(commonFlags.RuntimeConfigs)
			if err != nil {
				return fmt.Errorf("error creating local gadget manager: %w", commonutils.WrapInErrManagerInit(err))
			}
			defer localGadgetManager.Close()

			tracer, err := tracer.NewTracer(nil)
			if err != nil {
				return fmt.Errorf("error creating tracer: %w", err)
			}
			defer tracer.Stop()

			containers := localGadgetManager.GetContainersBySelector(&containercollection.ContainerSelector{
				Name: commonFlags.Containername,
			})
			for _, container := range containers {
				tracer.Attach(container.Mntns)
			}

			exit := make(chan os.Signal, 1)
			signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)

			enterPressed := make(chan bool, 1)

			go func() {
				fmt.Println("Press Enter to read perf buffers and Ctrl^C to quit.")

				for {
					fmt.Scanf("\n")
					enterPressed <- true
				}
			}()

			for {
				select {
				case <-enterPressed:
					for _, container := range containers {
						events, err := tracer.Read(container.Mntns)
						if err != nil {
							return err
						}
						for _, event := range events {
							fmt.Printf("%v\n", event)
						}
					}
				case <-exit:
					return nil
				}
			}
		},
	}

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}
