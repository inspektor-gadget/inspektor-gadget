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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
)

func TestProfileCpu(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-cpu-profile")

	var extraArgs string
	expectedEntry := &cpuprofileTypes.Report{Comm: "sh"}

	switch DefaultTestComponent {
	case IgTestComponent:
		expectedEntry.CommonData = BuildCommonData(ns,
			WithRuntimeMetadata(containerRuntime),
			WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime),
			WithPodLabels("test-pod", ns, isCrioRuntime),
		)
		extraArgs = fmt.Sprintf("--runtimes=%s", containerRuntime)
	case InspektorGadgetTestComponent:
		expectedEntry.CommonData = BuildCommonDataK8s(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime))
		extraArgs = fmt.Sprintf("-n %s -p test-pod", ns)
	}

	profileCPUCmd := &Command{
		Name: "ProfileCpu",
		Cmd:  fmt.Sprintf("%s profile cpu -K -o json --timeout 15 %s", DefaultTestComponent, extraArgs),
		ValidateOutput: func(t *testing.T, output string) {
			normalize := func(e *cpuprofileTypes.Report) {
				e.Pid = 0
				e.UserStack = nil
				e.KernelStack = nil
				e.Count = 0

				normalizeCommonData(&e.CommonData, ns)
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntry)
		},
	}

	commands := []TestStep{
		CreateTestNamespaceCommand(ns),
		BusyboxPodCommand(ns, "while true; do echo foo > /dev/null; done"),
		WaitUntilTestPodReadyCommand(ns),
		profileCPUCmd,
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
