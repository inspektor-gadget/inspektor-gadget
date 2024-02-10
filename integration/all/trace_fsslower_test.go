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
	tracefsslowerType "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/fsslower/types"
)

func TestTraceFsslower(t *testing.T) {
	fsType := "ext4"
	if *k8sDistro == K8sDistroARO && DefaultTestComponent == InspektorGadgetTestComponent {
		fsType = "xfs"
	}

	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-fsslower")

	commonDataOpts := []CommonDataOption{WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)}

	var extraArgs string
	switch DefaultTestComponent {
	case IgTestComponent:
		extraArgs = "--runtimes=" + containerRuntime
		commonDataOpts = append(commonDataOpts, WithRuntimeMetadata(containerRuntime))
	case InspektorGadgetTestComponent:
		extraArgs = "-n " + ns
	}

	fsslowerCmd := &Command{
		Name:         "StartTraceFsslowerGadget",
		Cmd:          fmt.Sprintf("%s trace fsslower -f %s -m 0 -o json %s", DefaultTestComponent, fsType, extraArgs),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedEntry := &tracefsslowerType.Event{
				Event: BuildBaseEvent(ns, commonDataOpts...),
				Comm:  "cat",
				File:  "foo",
				Op:    "R",
			}

			normalize := func(e *tracefsslowerType.Event) {
				e.Timestamp = 0
				e.MountNsID = 0
				e.Pid = 0
				e.Bytes = 0
				e.Offset = 0
				e.Latency = 0

				e.Runtime.ContainerID = ""
				e.Runtime.ContainerImageDigest = ""

				if DefaultTestComponent == IgTestComponent {
					prefixContainerName := "k8s_" + "test-pod" + "_" + "test-pod" + "_" + ns + "_"
					if (containerRuntime == ContainerRuntimeDocker || containerRuntime == ContainerRuntimeCRIO) &&
						strings.HasPrefix(e.Runtime.ContainerName, prefixContainerName) {
						e.Runtime.ContainerName = "test-pod"
					}

					if isDockerRuntime {
						e.Runtime.ContainerImageName = ""
					}
				} else if DefaultTestComponent == InspektorGadgetTestComponent {
					e.K8s.Node = ""
					// TODO: Verify container runtime and container name
					e.Runtime.RuntimeName = ""
					e.Runtime.ContainerName = ""
				}
			}

			ExpectEntriesToMatch(t, output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		fsslowerCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		BusyboxPodCommand(ns, "echo 'this is foo' > foo && while true; do cat foo && sleep 0.1; done"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
