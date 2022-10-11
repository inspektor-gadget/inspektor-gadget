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

	. "github.com/kinvolk/inspektor-gadget/integration"
	capabilitiesTypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
)

func TestTraceCapabilities(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-capabilities")

	capabilitiesCmd := &Command{
		Name:         "TraceCapabilities",
		Cmd:          fmt.Sprintf("local-gadget trace capabilities -o json --runtimes=%s", *containerRuntime),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &capabilitiesTypes.Event{
				Event:   BuildBaseEvent(ns),
				Comm:    "nice",
				CapName: "CAP_SYS_NICE",
				Cap:     23,
				Audit:   1,
				Verdict: "Deny",
			}

			normalize := func(e *capabilitiesTypes.Event) {
				// TODO: Handle it once we support getting K8s container name for docker
				// Issue: https://github.com/kinvolk/inspektor-gadget/issues/737
				if *containerRuntime == ContainerRuntimeDocker {
					e.Container = "test-pod"
				}

				e.Pid = 0
				e.UID = 0
				e.MountNsID = 0
				// Do not check InsetID to avoid introducing dependency on the kernel version
				e.InsetID = nil
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	// TODO: capabilitiesCmd should moved up the list once we can trace new cri-o containers.
	// Issue: https://github.com/kinvolk/inspektor-gadget/issues/1018
	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		BusyboxPodRepeatCommand(ns, "nice -n -20 echo"),
		WaitUntilTestPodReadyCommand(ns),
		capabilitiesCmd,
		DeleteTestNamespaceCommand(ns),
	}

	RunCommands(commands, t)
}
