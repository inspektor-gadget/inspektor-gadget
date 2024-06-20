// Copyright 2024 The Inspektor Gadget authors
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
	tracesignalTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/signal/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestTraceSignal(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-signal")

	var extraArgs string
	var expectedEvent eventtypes.Event
	switch DefaultTestComponent {
	case IgTestComponent:
		extraArgs = fmt.Sprintf("--runtimes=%s", containerRuntime)
		expectedEvent = BuildBaseEvent(ns,
			WithRuntimeMetadata(containerRuntime),
			WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime),
			WithPodLabels("test-pod", ns, isCrioRuntime),
		)
	case InspektorGadgetTestComponent:
		extraArgs = fmt.Sprintf("-n %s", ns)
		expectedEvent = BuildBaseEventK8s(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime))
	}

	traceSignalCmd := &Command{
		Name:         "TraceSignal",
		Cmd:          fmt.Sprintf("%s trace signal -o json %s", DefaultTestComponent, extraArgs),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedEntry := &tracesignalTypes.Event{
				Event:  expectedEvent,
				Comm:   "sh",
				Signal: "SIGTERM",
			}

			normalize := func(e *tracesignalTypes.Event) {
				e.Timestamp = 0
				e.Pid = 0
				e.TargetPid = 0
				e.Retval = 0
				e.MountNsID = 0

				normalizeCommonData(&e.CommonData, ns)
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntry)
		},
	}

	commands := []TestStep{
		CreateTestNamespaceCommand(ns),
		traceSignalCmd,
		SleepForSecondsCommand(2), // wait to ensure ig or kubectl-gadget has started
		BusyboxPodRepeatCommand(ns, "sleep 3 & kill $!"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
