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
	tracebindTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/bind/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
)

func TestTraceBind(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-bind")

	var extraArgs string
	expectedEntry := &tracebindTypes.Event{
		Comm:      "nc",
		Protocol:  "TCP",
		Addr:      "::",
		Port:      9090,
		Options:   ".R...",
		Interface: "",
		Uid:       1000,
		Gid:       1111,
	}

	switch DefaultTestComponent {
	case IgTestComponent:
		extraArgs = fmt.Sprintf("--runtimes=%s", containerRuntime)
		expectedEntry.Event = BuildBaseEvent(ns,
			WithRuntimeMetadata(containerRuntime),
			WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime),
			WithPodLabels("test-pod", ns, isCrioRuntime),
		)
	case InspektorGadgetTestComponent:
		extraArgs = fmt.Sprintf("-n %s", ns)
		expectedEntry.Event = BuildBaseEventK8s(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime))
	}

	traceBindCmd := &Command{
		Name:         "TraceBind",
		Cmd:          fmt.Sprintf("%s trace bind -o json %s", DefaultTestComponent, extraArgs),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			normalize := func(e *tracebindTypes.Event) {
				e.Timestamp = 0
				e.Pid = 0
				e.MountNsID = 0

				normalizeCommonData(&e.CommonData, ns)
			}

			// Since we aren't doing any filtering in traceBindCmd we avoid using MatchAllEntries
			// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/644
			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntry)
		},
	}

	commands := []TestStep{
		CreateTestNamespaceCommand(ns),
		traceBindCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		BusyboxPodRepeatCommand(ns, "setuidgid 1000:1111 nc -l -p 9090 -w 1"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
