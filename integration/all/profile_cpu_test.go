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
	profilecpuTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/cpu/types"
)

func TestProfileCpu(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-profile-cpu")

	commonDataOpts := []CommonDataOption{WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)}

	var extraArgs string
	switch DefaultTestComponent {
	case IgTestComponent:
		extraArgs = "--runtimes=" + containerRuntime
		commonDataOpts = append(commonDataOpts, WithRuntimeMetadata(containerRuntime))
	case InspektorGadgetTestComponent:
		extraArgs = "-n " + ns + " -p test-pod"
	}

	profileCPUCmd := &Command{
		Name: "RunProfileCpuGadget",
		Cmd:  fmt.Sprintf("%s profile cpu -K --timeout 10 -o json %s", DefaultTestComponent, extraArgs),
		ValidateOutput: func(t *testing.T, output string) {
			expectedEntry := &profilecpuTypes.Report{
				CommonData: BuildCommonData(ns, commonDataOpts...),
				Comm:       "sh",
			}

			normalize := func(e *profilecpuTypes.Report) {
				e.Pid = 0
				e.UserStack = nil
				e.KernelStack = nil
				e.Count = 0

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
		BusyboxPodCommand(ns, "while true; do echo foo > /dev/null; done"),
		WaitUntilTestPodReadyCommand(ns),
		profileCPUCmd,
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
