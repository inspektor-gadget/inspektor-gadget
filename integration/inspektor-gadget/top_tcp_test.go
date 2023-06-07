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
	"syscall"
	"testing"

	toptcpTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/tcp/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestTopTcp(t *testing.T) {
	ns := GenerateTestNamespaceName("test-top-tcp")

	t.Parallel()

	topTCPCmd := &Command{
		Name:         "StartTopTcpGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET top tcp -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &toptcpTypes.Stats{
				CommonData: BuildCommonData(ns),
				Comm:       "curl",
				Dport:      80,
				IPVersion:  syscall.AF_INET,
				Saddr:      "127.0.0.1",
				Daddr:      "127.0.0.1",
			}

			normalize := func(e *toptcpTypes.Stats) {
				e.MountNsID = 0
				e.Pid = 0
				e.Sport = 0
				e.Sent = 0
				e.Received = 0

				e.K8s.Node = ""
				// TODO: Verify container runtime and container name
				e.Runtime = types.BasicRuntimeMetadata{}
			}

			return ExpectEntriesInMultipleArrayToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		topTCPCmd,
		PodCommand("test-pod", "nginx", ns, "[sh, -c]", "nginx && while true; do curl 127.0.0.1; sleep 0.1; done"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
