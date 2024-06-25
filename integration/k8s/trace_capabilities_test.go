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
	capabilitiesTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
)

func TestTraceCapabilities(t *testing.T) {
	if *k8sDistro == K8sDistroARO {
		t.Skip("Skip running trace capabilities on ARO: See https://github.com/inspektor-gadget/inspektor-gadget/issues/985 for more details")
	}

	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-capabilities")

	var extraArgs string
	expectedEntry := &capabilitiesTypes.Event{
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

	switch DefaultTestComponent {
	case IgTestComponent:
		extraArgs = fmt.Sprintf("--runtimes=%s", containerRuntime)
		expectedEntry.Event = BuildBaseEvent(ns,
			WithRuntimeMetadata(containerRuntime),
			WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime),
			WithPodLabels("test-pod", ns, isCrioRuntime))
	case InspektorGadgetTestComponent:
		extraArgs = fmt.Sprintf("-n %s", ns)
		expectedEntry.Event = BuildBaseEventK8s(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime))
	}

	traceCapabilitiesCmd := &Command{
		Name:         "TraceCapabilities",
		Cmd:          fmt.Sprintf("%s trace capabilities -o json %s", DefaultTestComponent, extraArgs),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			normalize := func(e *capabilitiesTypes.Event) {
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

				normalizeCommonData(&e.CommonData, ns)
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntry)
		},
	}

	commands := []TestStep{
		CreateTestNamespaceCommand(ns),
		traceCapabilitiesCmd,
		SleepForSecondsCommand(2), // wait to ensure ig or kubectl-gadget has started
		BusyboxPodRepeatCommand(ns, "nice -n -20 echo"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
