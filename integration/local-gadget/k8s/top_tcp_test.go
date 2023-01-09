// Copyright 2022 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this tcp except in compliance with the License.
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

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/tcp/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestTopTCP(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-top-tcp")

	commandsPreTest := []*Command{
		CreateTestNamespaceCommand(ns),
		PodCommand("nginx-pod", "nginx", ns, "", ""),
		WaitUntilPodReadyCommand(ns, "nginx-pod"),
	}

	RunTestSteps(commandsPreTest, t)
	NginxIP := GetTestPodIP(ns, "nginx-pod")

	topTCPCmd := &Command{
		Name:         "TopTCP",
		Cmd:          fmt.Sprintf("local-gadget top tcp -o json -m 999 --runtimes=%s", *containerRuntime),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &types.Stats{
				CommonData: eventtypes.CommonData{
					Namespace: ns,
					Pod:       "test-pod",
				},
				Comm:   "wget",
				Family: syscall.AF_INET,
				Daddr:  NginxIP,
				Dport:  80,
			}

			normalize := func(e *types.Stats) {
				e.Container = ""
				e.Pid = 0
				e.MountNsID = 0
				e.Saddr = ""
				e.Sport = 0
				e.Sent = 0
				e.Received = 0
			}

			return ExpectEntriesInMultipleArrayToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		topTCPCmd,
		SleepForSecondsCommand(2), // wait to ensure local-gadget has started
		BusyboxPodRepeatCommand(ns, fmt.Sprintf("wget -q -O /dev/null %s:80", NginxIP)),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}
