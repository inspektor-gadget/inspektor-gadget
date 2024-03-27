// Copyright 2019-2022 The Inspektor Gadget authors
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
	"strings"
	"testing"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	snapshotprocessTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/process/types"
)

func TestSnapshotProcess(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-snapshot-process")

	commandsPreTest := []*Command{
		CreateTestNamespaceCommand(ns),
		BusyboxPodCommand(ns, "nc -l -p 9090"),
		WaitUntilTestPodReadyCommand(ns),
	}
	RunTestSteps(commandsPreTest, t, WithCbBeforeCleanup(PrintLogsFn(ns)))

	t.Cleanup(func() {
		commandsPostTest := []*Command{
			DeleteTestNamespaceCommand(ns),
		}
		RunTestSteps(commandsPostTest, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	commonDataOpts := []CommonDataOption{WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)}

	var extraArgs string
	var nodeName string
	switch DefaultTestComponent {
	case IgTestComponent:
		extraArgs = "--runtimes=" + containerRuntime
		commonDataOpts = append(commonDataOpts, WithRuntimeMetadata(containerRuntime))
	case InspektorGadgetTestComponent:
		nodeName = GetPodNode(t, ns, "test-pod")
		extraArgs = "-n " + ns + " --node " + nodeName
	}

	commands := []*Command{
		{
			Name:         "SnapshotProcess",
			Cmd:          fmt.Sprintf("%s snapshot process -o json %s", DefaultTestComponent, extraArgs),
			StartAndStop: true,
			ValidateOutput: func(t *testing.T, output string) {
				expectedEntry := &snapshotprocessTypes.Event{
					Event:   BuildBaseEvent(ns, commonDataOpts...),
					Command: "nc",
				}

				if DefaultTestComponent == InspektorGadgetTestComponent {
					expectedEntry.K8s.Node = nodeName
				}

				normalize := func(e *snapshotprocessTypes.Event) {

					e.Pid = 0
					e.Tid = 0
					e.ParentPid = 0
					e.MountNsID = 0

					e.Runtime.ContainerID = ""
					e.Runtime.ContainerImageDigest = ""

					if DefaultTestComponent == IgTestComponent {
						// Docker and CRI-O use a custom container name composed, among
						// other things, by the pod UID. We don't know the pod UID in
						// advance, so we can't match the exact expected container name.
						prefixContainerName := "k8s_" + "test-pod" + "_" + "test-pod" + "_" + ns + "_"
						if (containerRuntime == ContainerRuntimeDocker || containerRuntime == ContainerRuntimeCRIO) &&
							strings.HasPrefix(e.Runtime.ContainerName, prefixContainerName) {
							e.Runtime.ContainerName = "test-pod"
						}
						// Docker can provide different values for ContainerImageName. See `getContainerImageNamefromImage`
						if isDockerRuntime {
							e.Runtime.ContainerImageName = ""
						}
					} else if DefaultTestComponent == InspektorGadgetTestComponent {
						// TODO: Verify container runtime and container name
						e.Runtime.RuntimeName = ""
						e.Runtime.ContainerName = ""
					}
				}

				ExpectEntriesInArrayToMatch(t, output, normalize, expectedEntry)
			},
		},
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
