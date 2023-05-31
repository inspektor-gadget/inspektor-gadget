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
)

func TestTraceCapabilities(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-capabilities")

	capabilitiesCmd := &Command{
		Name:         "TraceCapabilities",
		Cmd:          fmt.Sprintf("ig trace capabilities -o json --runtimes=%s", *containerRuntime),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &capabilitiesTypes.Event{
				Event:         BuildBaseEvent(ns),
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

			normalize := func(e *capabilitiesTypes.Event) {
				// TODO: Handle it once we support getting K8s container name for docker
				// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/737
				if *containerRuntime == ContainerRuntimeDocker {
					e.K8s.Container = "test-pod"
				}

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
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		capabilitiesCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		BusyboxPodRepeatCommand(ns, "nice -n -20 echo"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
