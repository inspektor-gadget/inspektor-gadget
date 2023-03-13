// Copyright 2022-2023 The Inspektor Gadget authors
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

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/tcp/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func newTopTCPCmd(ns string, cmd string, startAndStop bool) *Command {
	expectedOutputFn := func(output string) error {
		expectedEntry := &types.Stats{
			CommonData: eventtypes.CommonData{
				Namespace: ns,
				Pod:       "test-pod",
			},
			Comm:   "curl",
			Family: syscall.AF_INET,
			Dport:  80,
			Saddr:  "127.0.0.1",
			Daddr:  "127.0.0.1",
		}

		normalize := func(e *types.Stats) {
			e.Container = ""
			e.Pid = 0
			e.MountNsID = 0
			e.Sport = 0
			e.Sent = 0
			e.Received = 0
		}

		return ExpectEntriesInMultipleArrayToMatch(output, normalize, expectedEntry)
	}

	return &Command{
		Name:             "TopTCP",
		ExpectedOutputFn: expectedOutputFn,
		Cmd:              cmd,
		StartAndStop:     startAndStop,
	}
}

func TestTopTCP(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-top-tcp")

	commandsPreTest := []*Command{
		CreateTestNamespaceCommand(ns),
		PodCommand("test-pod", "nginx", ns, "[sh, -c]", "nginx && while true; do curl 127.0.0.1; sleep 0.1; done"),
		WaitUntilTestPodReadyCommand(ns),
	}
	RunTestSteps(commandsPreTest, t, WithCbBeforeCleanup(PrintLogsFn(ns)))

	t.Cleanup(func() {
		commandsPostTest := []*Command{
			DeleteTestNamespaceCommand(ns),
		}
		RunTestSteps(commandsPostTest, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("StartAndStop", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("ig top tcp -o json -m 999 --runtimes=%s", *containerRuntime)
		topTCPCmd := newTopTCPCmd(ns, cmd, true)
		RunTestSteps([]*Command{topTCPCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("ig top tcp -o json -m 999 --runtimes=%s --timeout %d",
			*containerRuntime, timeout)
		topTCPCmd := newTopTCPCmd(ns, cmd, false)
		RunTestSteps([]*Command{topTCPCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("Interval=Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("ig top tcp -o json -m 999 --runtimes=%s --timeout %d --interval %d",
			*containerRuntime, timeout, timeout)
		topTCPCmd := newTopTCPCmd(ns, cmd, false)
		RunTestSteps([]*Command{topTCPCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})
}
