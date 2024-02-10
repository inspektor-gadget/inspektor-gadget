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

	tracecapabilitiesTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestTraceCapabilities(t *testing.T) {
	if *k8sDistro == K8sDistroARO {
		t.Skip("Skip running trace capabilities on ARO: See https://github.com/inspektor-gadget/inspektor-gadget/issues/985 for more details")
	}

	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-capabilities")

	commonDataOpts := []CommonDataOption{WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)}

	var extraArgs string
	switch DefaultTestComponent {
	case IgTestComponent:
		extraArgs = "--runtimes=" + containerRuntime
		commonDataOpts = append(commonDataOpts, WithRuntimeMetadata(containerRuntime))
	case InspektorGadgetTestComponent:
		extraArgs = "-n " + ns
	}

	traceCapabilitiesCmd := &Command{
		Name:         "StartTraceCapabilitiesGadget",
		Cmd:          fmt.Sprintf("%s trace capabilities -o json %s", DefaultTestComponent, extraArgs),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedEntry := &tracecapabilitiesTypes.Event{
				Event:         BuildBaseEvent(ns, commonDataOpts...),
				Comm:          "nice",
				CapName:       "SYS_NICE",
				Cap:           23,
				Syscall:       "setpriority",
				Audit:         1,
				Verdict:       "Deny",
				CurrentUserNs: 1,
				TargetUserNs:  1,
				Caps:          1,
				CapsNames:     []string{"x"},
			}

			normalize := func(e *tracecapabilitiesTypes.Event) {
				e.Timestamp = 0
				e.Pid = 0
				e.Uid = 0
				e.MountNsID = 0
				// Do not check InsetID to avoid introducing dependency on the kernel version
				e.InsetID = nil

				if e.CurrentUserNs != 0 {
					e.CurrentUserNs = 1
				}
				if e.TargetUserNs != 0 {
					e.TargetUserNs = 1
				}
				if e.Caps > 0 {
					e.Caps = 1
				}
				if len(e.CapsNames) != 0 {
					e.CapsNames = []string{"x"}
				}

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

			ExpectEntriesToMatch(t, output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		traceCapabilitiesCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		BusyboxPodRepeatCommand(ns, "nice -n -20 echo"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
