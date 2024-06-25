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
	snapshotprocessTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/process/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
)

func TestSnapshotProcess(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-snapshot-process")

	commandsPreTest := []TestStep{
		CreateTestNamespaceCommand(ns),
		BusyboxPodCommand(ns, "nc -l -p 9090"),
		WaitUntilTestPodReadyCommand(ns),
	}
	RunTestSteps(commandsPreTest, t, WithCbBeforeCleanup(PrintLogsFn(ns)))

	t.Cleanup(func() {
		commandsPostTest := []TestStep{
			DeleteTestNamespaceCommand(ns),
		}
		RunTestSteps(commandsPostTest, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	var extraArgs string
	var nodeName string
	expectedEntry := &snapshotprocessTypes.Event{Command: "nc"}

	switch DefaultTestComponent {
	case IgTestComponent:
		extraArgs = fmt.Sprintf("--runtimes=%s", containerRuntime)
		expectedEntry.Event = BuildBaseEvent(ns,
			WithRuntimeMetadata(containerRuntime),
			WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime),
			WithPodLabels("test-pod", ns, isCrioRuntime),
		)
	case InspektorGadgetTestComponent:
		nodeName = GetPodNode(t, ns, "test-pod")
		extraArgs = fmt.Sprintf("-n %s --node %s", ns, nodeName)
		expectedEntry.Event = BuildBaseEventK8s(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime))
		expectedEntry.K8s.Node = nodeName
	}

	snapshotProcessCmd := &Command{
		Name:         "SnapshotProcess",
		Cmd:          fmt.Sprintf("%s snapshot process -o json %s", DefaultTestComponent, extraArgs),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			normalize := func(e *snapshotprocessTypes.Event) {
				e.Pid = 0
				e.Tid = 0
				e.ParentPid = 0
				e.MountNsID = 0

				normalizeCommonData(&e.CommonData, ns)

				e.K8s.Node = nodeName
			}

			match.MatchEntries(t, match.JSONSingleArrayMode, output, normalize, expectedEntry)
		},
	}

	RunTestSteps([]TestStep{snapshotProcessCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
