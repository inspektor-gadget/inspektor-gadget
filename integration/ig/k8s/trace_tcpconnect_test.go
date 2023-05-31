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
	tcpconnectTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcpconnect/types"
)

func TestTraceTcpconnect(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-tcpconnect")

	tcpconnectCmd := &Command{
		Name:         "StartTcpconnectGadget",
		Cmd:          fmt.Sprintf("ig trace tcpconnect -o json --runtimes=%s", *containerRuntime),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &tcpconnectTypes.Event{
				Event:     BuildBaseEvent(ns),
				Comm:      "curl",
				IPVersion: 4,
				Saddr:     "127.0.0.1",
				Daddr:     "127.0.0.1",
				Dport:     80,
			}

			normalize := func(e *tcpconnectTypes.Event) {
				// TODO: Handle it once we support getting K8s container name for docker
				// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/737
				if *containerRuntime == ContainerRuntimeDocker {
					e.K8s.Container = "test-pod"
				}

				e.Timestamp = 0
				e.Pid = 0
				e.Sport = 0
				e.MountNsID = 0
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		tcpconnectCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		PodCommand("test-pod", "nginx", ns, "[sh, -c]", "nginx && while true; do curl 127.0.0.1; sleep 0.1; done"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}

func TestTraceTcpconnect_latency(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-tcpconnect")

	tcpconnectCmd := &Command{
		Name:         "StartTcpconnectGadget",
		Cmd:          fmt.Sprintf("ig trace tcpconnect --latency -o json --runtimes=%s", *containerRuntime),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &tcpconnectTypes.Event{
				Event:     BuildBaseEvent(ns),
				Comm:      "curl",
				IPVersion: 4,
				Saddr:     "127.0.0.1",
				Daddr:     "127.0.0.1",
				Dport:     80,
				// Don't check the exact values but check that they aren't empty
				Latency: 1,
			}

			normalize := func(e *tcpconnectTypes.Event) {
				// TODO: Handle it once we support getting K8s container name for docker
				// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/737
				if *containerRuntime == ContainerRuntimeDocker {
					e.K8s.Container = "test-pod"
				}

				e.Timestamp = 0
				e.Pid = 0
				e.Sport = 0
				e.MountNsID = 0
				if e.Latency > 0 {
					e.Latency = 1
				}
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		tcpconnectCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		PodCommand("test-pod", "nginx", ns, "[sh, -c]", "nginx && while true; do curl 127.0.0.1; sleep 0.1; done"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
