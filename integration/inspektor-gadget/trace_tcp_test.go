// Copyright 2019-2022 The Inspektor Gadget authors
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

	tracetcpTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcp/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestTraceTcp(t *testing.T) {
	ns := GenerateTestNamespaceName("test-trace-tcp")

	t.Parallel()

	traceTCPCmd := &Command{
		Name:         "StartTraceTcpGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace tcp -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &tracetcpTypes.Event{
				Event:     BuildBaseEvent(ns),
				Comm:      "curl",
				IPVersion: 4,
				Dport:     80,
				Operation: "connect",
				Saddr:     "127.0.0.1",
				Daddr:     "127.0.0.1",
			}

			normalize := func(e *tracetcpTypes.Event) {
				e.Timestamp = 0
				e.K8s.Node = ""
				e.Pid = 0
				e.Sport = 0
				e.MountNsID = 0
			}

			fmt.Printf("output: %s\n", output)

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		traceTCPCmd,
		// TODO: can't use setuidgid because it's not available on the nginx image
		PodCommand("test-pod", "nginx", ns, "[sh, -c]", "nginx && while true; do curl 127.0.0.1; sleep 0.1; done"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
