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
	"strings"
	"testing"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	bindTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/bind/types"
)

func TestTraceBind(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-bind")

	commonDataOpts := []CommonDataOption{WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)}

	var extraArgs string
	var busyboxCmd string
	switch DefaultTestComponent {
	case IgTestComponent:
		extraArgs = "--runtimes=" + containerRuntime
		commonDataOpts = append(commonDataOpts, WithRuntimeMetadata(containerRuntime))
		busyboxCmd = "nc -l -p 9090 -w 1"
	case InspektorGadgetTestComponent:
		extraArgs = "-n " + ns
		busyboxCmd = "setuidgid 1000:1111 nc -l -p 9090 -w 1"
	}

	traceBindCmd := &Command{
		Name:         "TraceBind",
		Cmd:          fmt.Sprintf("%s trace bind -o json %s", DefaultTestComponent, extraArgs),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedEntry := &bindTypes.Event{
				Event:    BuildBaseEvent(ns, commonDataOpts...),
				Comm:     "nc",
				Protocol: "TCP",
				Addr:     "::",
				Port:     9090,
				Options:  ".R...",
			}

			if DefaultTestComponent == InspektorGadgetTestComponent {
				expectedEntry.Interface = ""
				expectedEntry.Uid = 1000
				expectedEntry.Gid = 1111
			}

			normalize := func(e *bindTypes.Event) {

				e.Timestamp = 0
				e.Pid = 0
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
					e.K8s.Node = ""
					// TODO: Verify container runtime and container name
					e.Runtime.RuntimeName = ""
					e.Runtime.ContainerName = ""
				}
			}

			// Since we aren't doing any filtering in traceBindCmd we avoid using ExpectAllToMatch
			// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/644
			ExpectEntriesToMatch(t, output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		traceBindCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		BusyboxPodRepeatCommand(ns, busyboxCmd),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
