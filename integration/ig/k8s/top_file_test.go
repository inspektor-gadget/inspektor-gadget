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
	"testing"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/file/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func newTopFileCmd(ns string, cmd string, startAndStop bool) *Command {
	expectedOutputFn := func(output string) error {
		expectedEntry := &types.Stats{
			CommonData: eventtypes.CommonData{
				Namespace: ns,
				Pod:       "test-pod",
			},
			// echo is built-in
			Comm:     "sh",
			Filename: "bar",
			FileType: 'R',
		}

		normalize := func(e *types.Stats) {
			e.Container = ""
			e.Pid = 0
			e.Tid = 0
			e.MountNsID = 0
			e.Reads = 0
			e.ReadBytes = 0
			e.Writes = 0
			e.WriteBytes = 0
		}

		return ExpectEntriesInMultipleArrayToMatch(output, normalize, expectedEntry)
	}

	return &Command{
		Name:             "TopFile",
		ExpectedOutputFn: expectedOutputFn,
		Cmd:              cmd,
		StartAndStop:     startAndStop,
	}
}

func TestTopFile(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-top-file")

	commandsPreTest := []*Command{
		CreateTestNamespaceCommand(ns),
		BusyboxPodRepeatCommand(ns, "echo foo > bar"),
		WaitUntilTestPodReadyCommand(ns),
	}
	RunTestSteps(commandsPreTest, t, WithCbBeforeCleanup(PrintLogsFn(ns)))

	t.Cleanup(func() {
		commandsPostTest := []*Command{
			DeleteTestNamespaceCommand(ns),
		}
		RunTestSteps(commandsPostTest, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	// TODO: Filter by namespace to avoid interferences with events from other
	// tests. In the meanwhile, given that we are generating events by writing
	// into a file:
	// 	(1) Increase max-rows to 999 (default is 20)
	// 	(2) Sort by "-writes,-wbytes" (default is "-reads,-writes,-rbytes,-wbytes")

	t.Run("StartAndStop", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("ig top file -o json --sort -writes,-wbytes -m 999 --runtimes=%s", *containerRuntime)
		topFileCmd := newTopFileCmd(ns, cmd, true)
		RunTestSteps([]*Command{topFileCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("ig top file -o json --sort -writes,-wbytes -m 999 --runtimes=%s --timeout %d",
			*containerRuntime, timeout)
		topFileCmd := newTopFileCmd(ns, cmd, false)
		RunTestSteps([]*Command{topFileCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("Interval=Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("ig top file -o json --sort -writes,-wbytes -m 999 --runtimes=%s --timeout %d --interval %d",
			*containerRuntime, timeout, timeout)
		topFileCmd := newTopFileCmd(ns, cmd, false)
		RunTestSteps([]*Command{topFileCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})
}
