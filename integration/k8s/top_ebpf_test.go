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
	topebpfTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
)

func newTopEbpfCmd(cmd string, startAndStop bool) *Command {
	validateOutputFn := func(t *testing.T, output string) {
		expectedEntry := &topebpfTypes.Stats{
			Type: ebpf.Tracing.String(),
			Name: "ig_top_ebpf_it",
		}

		normalize := func(e *topebpfTypes.Stats) {
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
			e.TotalCpuUsage = 0
			e.PerCpuUsage = 0

			if DefaultTestComponent == InspektorGadgetTestComponent {
				e.K8s.Node = ""
			}
		}

		match.MatchEntries(t, match.JSONMultiArrayMode, output, normalize, expectedEntry)
	}

	return &Command{
		Name:           "TopEbpf",
		ValidateOutput: validateOutputFn,
		Cmd:            cmd,
		StartAndStop:   startAndStop,
	}
}

func TestTopEbpf(t *testing.T) {
	if *k8sDistro == K8sDistroAKSUbuntu && *k8sArch == "amd64" {
		t.Skip("Skip running top ebpf gadget on AKS Ubuntu amd64: see issue #931")
	}

	t.Parallel()

	var extraArgs string
	if DefaultTestComponent == IgTestComponent {
		extraArgs = fmt.Sprintf("--runtimes=%s", containerRuntime)
	}

	t.Run("StartAndStop", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("%s top ebpf -o json -m 100 %s", DefaultTestComponent, extraArgs)
		topEbpfCmd := newTopEbpfCmd(cmd, true)
		RunTestSteps([]TestStep{topEbpfCmd}, t, WithCbBeforeCleanup(PrintLogsFn()))
	})

	t.Run("Timeout", func(t *testing.T) {
		t.Parallel()

		// TODO: Filter by namespace to avoid interferences with events from other
		// tests. In the meanwhile, given that we are generating events by writing
		// into a file:
		// 	(1) Increase max-rows to 999 (default is 20)
		cmd := fmt.Sprintf("%s top ebpf -o json -m %d --timeout %d %s",
			DefaultTestComponent, maxRows, timeout, extraArgs)
		topEbpfCmd := newTopEbpfCmd(cmd, false)
		RunTestSteps([]TestStep{topEbpfCmd}, t, WithCbBeforeCleanup(PrintLogsFn()))
	})

	t.Run("Interval=Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("%s top ebpf -o json -m %d --timeout %d --interval %d %s",
			DefaultTestComponent, maxRows, timeout, timeout, extraArgs)
		topEbpfCmd := newTopEbpfCmd(cmd, false)
		RunTestSteps([]TestStep{topEbpfCmd}, t, WithCbBeforeCleanup(PrintLogsFn()))
	})
}
