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

package snapshot

import (
	"fmt"

	"github.com/spf13/cobra"

	commonsnapshot "github.com/kinvolk/inspektor-gadget/cmd/common/snapshot"
	"github.com/kinvolk/inspektor-gadget/cmd/local-gadget/utils"
	containercollection "github.com/kinvolk/inspektor-gadget/pkg/container-collection"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/snapshot/socket/tracer"
	socketTypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/snapshot/socket/types"
	localgadgetmanager "github.com/kinvolk/inspektor-gadget/pkg/local-gadget-manager"
)

func newSocketCmd() *cobra.Command {
	var commonFlags utils.CommonFlags
	var flags commonsnapshot.SocketFlags

	runCmd := func(*cobra.Command, []string) error {
		socketGadget := &SnapshotGadget[socketTypes.Event]{
			SnapshotGadgetPrinter: commonsnapshot.SnapshotGadgetPrinter[socketTypes.Event]{
				Parser: commonsnapshot.NewSocketParserWithRuntimeInfo(&commonFlags.OutputConfig, &flags),
			},
			commonFlags: &commonFlags,
			runTracer: func(localGadgetManager *localgadgetmanager.LocalGadgetManager, containerSelector *containercollection.ContainerSelector) ([]socketTypes.Event, error) {
				allSockets := []socketTypes.Event{}

				// Given that the tracer works per network namespace, we only
				// need to run it once per namespace.
				visitedNetNs := make(map[uint64]struct{})

				filteredContainers := localGadgetManager.GetContainersBySelector(containerSelector)
				if len(filteredContainers) == 0 {
					return nil, fmt.Errorf("no container matched the requested filter")
				}

				for _, container := range filteredContainers {
					// Make the whole gadget fail if there is a container
					// without PID because it would be an inconsistency that has
					// to be notified.
					if container.Pid == 0 {
						return nil, fmt.Errorf("container %q does not have PID",
							container.KubernetesContainerName)
					}

					if _, ok := visitedNetNs[container.Netns]; ok {
						continue
					}

					visitedNetNs[container.Netns] = struct{}{}

					netNsSockets, err := tracer.RunCollector(
						container.Pid,
						container.KubernetesPodName,
						container.KubernetesNamespace,
						"",
						flags.ParsedProtocol,
					)
					if err != nil {
						return nil, fmt.Errorf("running collector on pid %d: %w", container.Pid, err)
					}

					allSockets = append(allSockets, netNsSockets...)
				}

				return allSockets, nil
			},
		}

		return socketGadget.Run()
	}

	cmd := commonsnapshot.NewSocketCmd(runCmd, &flags)

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}
