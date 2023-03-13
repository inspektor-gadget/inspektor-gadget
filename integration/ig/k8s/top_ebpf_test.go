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

	"github.com/cilium/ebpf"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/types"
)

func newTopEbpfCmd(cmd string, startAndStop bool) *Command {
	expectedOutputFn := func(output string) error {
		expectedEntry := &types.Stats{
			Type: ebpf.Tracing.String(),
			Name: "ig_top_ebpf_it",
		}

		normalize := func(e *types.Stats) {
			e.ProgramID = 0
			e.Processes = nil
			e.CurrentRuntime = 0
			e.CurrentRunCount = 0
			e.CumulativeRuntime = 0
			e.CumulativeRunCount = 0
			e.TotalRuntime = 0
			e.TotalRunCount = 0
			e.MapMemory = 0
			e.MapCount = 0
		}

		return ExpectEntriesInMultipleArrayToMatch(output, normalize, expectedEntry)
	}

	return &Command{
		Name:             "TopEbpf",
		ExpectedOutputFn: expectedOutputFn,
		Cmd:              cmd,
		StartAndStop:     startAndStop,
	}
}

func TestTopEbpf(t *testing.T) {
	t.Parallel()

	t.Run("StartAndStop", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("ig top ebpf -o json --runtimes=%s -m 100", *containerRuntime)
		topEbpfCmd := newTopEbpfCmd(cmd, true)
		RunTestSteps([]*Command{topEbpfCmd}, t, WithCbBeforeCleanup(PrintLogsFn()))
	})

	t.Run("Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("ig top ebpf -o json --runtimes=%s -m 100 --timeout %d",
			*containerRuntime, timeout)
		topEbpfCmd := newTopEbpfCmd(cmd, false)
		RunTestSteps([]*Command{topEbpfCmd}, t, WithCbBeforeCleanup(PrintLogsFn()))
	})

	t.Run("Interval=Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("ig top ebpf -o json --runtimes=%s -m 100 --timeout %d --interval %d",
			*containerRuntime, timeout, timeout)
		topEbpfCmd := newTopEbpfCmd(cmd, false)
		RunTestSteps([]*Command{topEbpfCmd}, t, WithCbBeforeCleanup(PrintLogsFn()))
	})
}
