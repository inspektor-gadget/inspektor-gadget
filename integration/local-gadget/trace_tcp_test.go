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
	tcpTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcp/types"
)

func TestTraceTCP(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-tcp")

	traceTCPCmd := &Command{
		Name:         "TraceTCP",
		Cmd:          fmt.Sprintf("local-gadget trace tcp -o json --runtimes=%s", *containerRuntime),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntries := []*tcpTypes.Event{
				{
					Event:     BuildBaseEvent(ns),
					Comm:      "wget",
					IPVersion: 4,
					Daddr:     "1.1.1.1",
					Dport:     80,
					Operation: "connect",
				},
				{
					Event:     BuildBaseEvent(ns),
					Comm:      "wget",
					IPVersion: 4,
					Daddr:     "1.1.1.1",
					Dport:     80,
					Operation: "close",
				},
				{
					Event:     BuildBaseEvent(ns),
					Comm:      "wget",
					IPVersion: 4,
					Daddr:     "1.1.1.1",
					Dport:     443,
					Operation: "connect",
				},
			}

			normalize := func(e *tcpTypes.Event) {
				// TODO: Handle it once we support getting K8s container name for docker
				// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/737
				if *containerRuntime == ContainerRuntimeDocker {
					e.Container = "test-pod"
				}

				e.Pid = 0
				e.Saddr = ""
				e.Sport = 0
				e.MountNsID = 0
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntries...)
		},
	}

	// TODO: traceTCPCmd should moved up the list once we can trace new cri-o containers.
	// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/1018
	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		BusyboxPodRepeatCommand(ns, "wget -q -O /dev/null -T 3 http://1.1.1.1"),
		WaitUntilTestPodReadyCommand(ns),
		traceTCPCmd,
		DeleteTestNamespaceCommand(ns),
	}

	RunCommands(commands, t)
}
