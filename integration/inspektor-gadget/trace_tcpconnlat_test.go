// Copyright 2023 The Inspektor Gadget authors
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

	tracetcpconnlatTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcpconnlat/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestTraceTcpconnlat(t *testing.T) {
	ns := GenerateTestNamespaceName("test-tcpconnlat")

	t.Parallel()

	traceTcpconnlatCmd := &Command{
		Name:         "StartTraceTcpconnlatGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace tcpconnlat -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &tracetcpconnlatTypes.Event{
				Event:     BuildBaseEvent(ns),
				Comm:      "curl",
				IPVersion: 4,
				Dport:     80,
				Saddr:     "127.0.0.1",
				Daddr:     "127.0.0.1",
				// Don't check the exact values but check that they aren't empty
				Latency: 1,
				Sport:   1,
			}

			normalize := func(e *tracetcpconnlatTypes.Event) {
				e.Timestamp = 0
				e.Node = ""
				e.Pid = 0
				e.Tid = 0
				e.MountNsID = 0
				if e.Latency > 0 {
					e.Latency = 1
				}
				if e.Sport > 0 {
					e.Sport = 1
				}
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		traceTcpconnlatCmd,
		PodCommand("test-pod", "nginx", ns, "[sh, -c]", "nginx && while true; do curl 127.0.0.1; sleep 0.1; done"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
