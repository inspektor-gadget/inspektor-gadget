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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/process/types"
)

func TestSnapshotProcess(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-snapshot-process")

	snapshotProcessCmd := &Command{
		Name:         "SnapshotProcess",
		Cmd:          fmt.Sprintf("ig snapshot process -o json --runtimes=%s", *containerRuntime),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &types.Event{
				Event:   BuildBaseEvent(ns),
				Command: "nc",
			}
			expectedEntry.Event.K8s.Container = ""

			normalize := func(e *types.Event) {
				e.K8s.Node = ""
				e.K8s.Container = ""
				e.Pid = 0
				e.Tid = 0
				e.ParentPid = 0
				e.MountNsID = 0
			}

			return ExpectEntriesInArrayToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		BusyboxPodCommand(ns, "nc -l -p 9090"),
		WaitUntilTestPodReadyCommand(ns),
		snapshotProcessCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
