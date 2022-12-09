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
	"testing"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	cpuprofileTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/cpu/types"
)

func TestProfileCpu(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-cpu-profile")

	profileCPUCmd := &Command{
		Name: "ProfileCpu",
		Cmd:  fmt.Sprintf("local-gadget profile cpu -K -o json --runtimes=%s --timeout 10", *containerRuntime),
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &cpuprofileTypes.Report{
				CommonData: BuildCommonData(ns),
				Comm:       "sh",
			}

			normalize := func(e *cpuprofileTypes.Report) {
				// TODO: Handle it once we support getting K8s container name for docker
				// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/737
				if *containerRuntime == ContainerRuntimeDocker {
					e.Container = "test-pod"
				}

				e.Node = ""
				e.Pid = 0
				e.UserStack = nil
				e.KernelStack = nil
				e.Count = 0
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		BusyboxPodCommand(ns, "while true; do echo foo > /dev/null; done"),
		WaitUntilTestPodReadyCommand(ns),
		profileCPUCmd,
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}
