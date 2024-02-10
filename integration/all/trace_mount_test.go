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
	tracemountTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/mount/types"
)

func TestTraceMount(t *testing.T) {

	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-mount")

	commonDataOpts := []CommonDataOption{WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)}

	var extraArgs string
	switch DefaultTestComponent {
	case IgTestComponent:
		extraArgs = "--runtimes=" + containerRuntime
		commonDataOpts = append(commonDataOpts, WithRuntimeMetadata(containerRuntime))
	case InspektorGadgetTestComponent:
		extraArgs = "-n " + ns
	}
	traceMountCmd := &Command{
		Name:         "StartTraceMountGadget",
		Cmd:          fmt.Sprintf("%s trace mount -o json %s", DefaultTestComponent, extraArgs),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedEntry := &tracemountTypes.Event{
				Event:     BuildBaseEvent(ns, commonDataOpts...),
				Comm:      "mount",
				Operation: "mount",
				Retval:    -2,
				Source:    "/mnt",
				Target:    "/mnt",
			}

			if DefaultTestComponent == IgTestComponent {
				expectedEntry.Flags = []string{"MS_SILENT"}
			}

			normalize := func(e *tracemountTypes.Event) {
				e.Timestamp = 0
				e.Pid = 0
				e.Tid = 0
				e.MountNsID = 0
				e.Latency = 0
				e.Fs = ""

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
					e.Data = ""
					e.Flags = nil
					e.FlagsRaw = 0

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
		traceMountCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		BusyboxPodRepeatCommand(ns, "mount /mnt /mnt"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
