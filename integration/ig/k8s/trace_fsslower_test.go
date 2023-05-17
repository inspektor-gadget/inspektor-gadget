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
	fsslowerTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/fsslower/types"
)

func TestTraceFsslower(t *testing.T) {
	// TODO: does it work in all cases?
	fsType := "ext4"

	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-fsslower")

	traceFsslowerCmd := &Command{
		Name:         "TraceFsslower",
		Cmd:          fmt.Sprintf("ig trace fsslower -f %s --runtimes=%s -m 0 -o json", fsType, *containerRuntime),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &fsslowerTypes.Event{
				Event: BuildBaseEvent(ns),
				Comm:  "cat",
				File:  "foo",
				Op:    "R",
			}

			normalize := func(e *fsslowerTypes.Event) {
				// TODO: Handle it once we support getting K8s container name for docker
				// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/737
				if *containerRuntime == ContainerRuntimeDocker {
					e.Container = "test-pod"
				}

				e.Timestamp = 0
				e.MountNsID = 0
				e.Pid = 0
				e.Bytes = 0
				e.Offset = 0
				e.Latency = 0
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		traceFsslowerCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		BusyboxPodCommand(ns, "echo 'this is foo' > foo && while true; do cat foo && sleep 0.1; done"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
