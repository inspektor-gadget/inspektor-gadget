// Copyright 2019-2023 The Inspektor Gadget authors
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
	tracesniTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/sni/types"
)

func TestTraceSni(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-sni")

	commonDataOpts := []CommonDataOption{WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)}

	var extraArgs string
	var busyboxCmd string
	switch DefaultTestComponent {
	case IgTestComponent:
		extraArgs = "--runtimes=" + containerRuntime
		commonDataOpts = append(commonDataOpts, WithRuntimeMetadata(containerRuntime))
		busyboxCmd = "wget --no-check-certificate -T 2 -q -O /dev/null https://kubernetes.default.svc.cluster.local"
	case InspektorGadgetTestComponent:
		extraArgs = "-n " + ns
		busyboxCmd = "setuidgid 1000:1111 wget --no-check-certificate -T 2 -q -O /dev/null https://inspektor-gadget.io"
	}

	traceSniCmd := &Command{
		Name:         "StartTraceSniGadget",
		Cmd:          fmt.Sprintf("%s trace sni -o json %s", DefaultTestComponent, extraArgs),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedEntry := &tracesniTypes.Event{
				Event: BuildBaseEvent(ns, commonDataOpts...),
				Comm:  "wget",
			}

			if DefaultTestComponent == IgTestComponent {
				expectedEntry.Name = "kubernetes.default.svc.cluster.local"
			} else if DefaultTestComponent == InspektorGadgetTestComponent {
				expectedEntry.Uid = 1000
				expectedEntry.Gid = 1111
				expectedEntry.Name = "inspektor-gadget.io"
			}

			normalize := func(e *tracesniTypes.Event) {
				e.Timestamp = 0
				e.MountNsID = 0
				e.NetNsID = 0
				e.Pid = 0
				e.Tid = 0

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

			if DefaultTestComponent == IgTestComponent {
				ExpectEntriesToMatch(t, output, normalize, expectedEntry)
			} else if DefaultTestComponent == InspektorGadgetTestComponent {
				ExpectAllToMatch(t, output, normalize, expectedEntry)
			}
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		traceSniCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		BusyboxPodRepeatCommand(ns, busyboxCmd),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
