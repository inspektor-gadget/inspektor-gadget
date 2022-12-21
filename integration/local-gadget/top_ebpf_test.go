// Copyright 2022 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this ebpf except in compliance with the License.
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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/types"
)

func TestTopEbpf(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-top-ebpf")

	topEbpfCmd := &Command{
		Name:         "TopEbpf",
		Cmd:          fmt.Sprintf("local-gadget top ebpf -o json --runtimes=%s", *containerRuntime),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			// Top gadgets truncate their output to 20 rows by default
			// Even if we increase the amount or rows, the output might get
			// truncated since we run the tests in parallel and we won't be
			// able to find our own eBPF program "ig_top_ebpf_it"
			expectedEntry := &types.Stats{}

			normalize := func(e *types.Stats) {
				e.Node = ""
				e.Namespace = ""
				e.Pod = ""
				e.Container = ""
				e.Namespace = ""
				e.ProgramID = 0
				e.Name = ""
				e.Type = ""
				e.Pids = nil
				e.CurrentRuntime = 0
				e.CurrentRunCount = 0
				e.CumulativeRuntime = 0
				e.CumulativeRunCount = 0
				e.TotalRuntime = 0
				e.TotalRunCount = 0
				e.MapMemory = 0
				e.MapCount = 0
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		topEbpfCmd,
		SleepForSecondsCommand(2), // wait to ensure local-gadget has started
		BusyboxPodRepeatCommand(ns, "echo foo > bar"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunCommands(commands, t)
}
