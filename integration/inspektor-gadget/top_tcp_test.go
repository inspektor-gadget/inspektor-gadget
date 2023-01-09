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

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestTopTcp(t *testing.T) {
	ns := GenerateTestNamespaceName("test-top-tcp")

	t.Parallel()

	commandsPreTest := []*Command{
		CreateTestNamespaceCommand(ns),
		PodCommand("nginx-pod", "nginx", ns, "", ""),
		WaitUntilPodReadyCommand(ns, "nginx-pod"),
	}

	RunTestSteps(commandsPreTest, t)
	NginxIP := GetTestPodIP(ns, "nginx-pod")

	topTCPCmd := &Command{
		Name:         "StartTopTcpGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET top tcp -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			TestPodIP := GetTestPodIP(ns, "test-pod")

			expectedEntry := &toptcpTypes.Stats{
				CommonData: BuildCommonData(ns),
				Comm:       "wget",
				Dport:      80,
				Family:     syscall.AF_INET,
				Saddr:      TestPodIP,
				Daddr:      NginxIP,
			}

			normalize := func(e *toptcpTypes.Stats) {
				e.Node = ""
				e.MountNsID = 0
				e.Pid = 0
				e.Sport = 0
				e.Sent = 0
				e.Received = 0
			}

			return ExpectEntriesInMultipleArrayToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		topTCPCmd,
		BusyboxPodRepeatCommand(ns, fmt.Sprintf("wget -q -O /dev/null %s:80", NginxIP)),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}
