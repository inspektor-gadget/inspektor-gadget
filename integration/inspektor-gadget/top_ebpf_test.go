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
	"testing"

	topebpfTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/types"

	"github.com/cilium/ebpf"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestTopEbpf(t *testing.T) {
	if *k8sDistro == K8sDistroAKSUbuntu && *k8sArch == "amd64" {
		t.Skip("Skip running top ebpf gadget on AKS Ubuntu amd64: see issue #931")
	}

	t.Parallel()

	topebpfCmd := &Command{
		Name:         "StartTopEbpfGadget",
		Cmd:          "$KUBECTL_GADGET top ebpf -o json -m 100",
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &topebpfTypes.Stats{
				Type: ebpf.Tracing.String(),
				Name: "ig_top_ebpf_it",
			}

			normalize := func(e *topebpfTypes.Stats) {
				e.Node = ""
				e.Namespace = ""
				e.Pod = ""
				e.Container = ""
				e.Namespace = ""
				e.ProgramID = 0
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

			return ExpectEntriesInMultipleArrayToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		topebpfCmd,
		SleepForSecondsCommand(2),
	}

	RunTestSteps(commands, t)
}
