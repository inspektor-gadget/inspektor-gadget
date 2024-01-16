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

	"github.com/cilium/ebpf"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	topebpfTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
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

			e.K8s = types.K8sMetadata{}
			// TODO: Verify container runtime and container name
			e.Runtime.RuntimeName = ""
			e.Runtime.ContainerName = ""
			e.Runtime.ContainerID = ""
			e.Runtime.ContainerImageDigest = ""
		}

		ExpectEntriesInMultipleArrayToMatch(t, output, normalize, expectedEntry)
	}
	return &Command{
		Name:           "TopEbpf",
		Cmd:            cmd,
		StartAndStop:   startAndStop,
		ValidateOutput: validateOutputFn,
	}
}

func TestTopEbpf(t *testing.T) {
	if *k8sDistro == K8sDistroAKSUbuntu && *k8sArch == "amd64" {
		t.Skip("Skip running top ebpf gadget on AKS Ubuntu amd64: see issue #931")
	}

	t.Parallel()

	t.Run("StartAndStop", func(t *testing.T) {
		t.Parallel()

		cmd := "$KUBECTL_GADGET top ebpf -o json -m 100"
		topEbpfCmd := newTopEbpfCmd(cmd, true)
		RunTestSteps([]*Command{topEbpfCmd}, t)
	})

	t.Run("Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("$KUBECTL_GADGET top ebpf -o json -m 999 --timeout %d", topTimeoutInSeconds)
		topEbpfCmd := newTopEbpfCmd(cmd, false)
		RunTestSteps([]*Command{topEbpfCmd}, t)
	})

	t.Run("Interval=Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("$KUBECTL_GADGET top ebpf -o json -m 999 --timeout %d --interval %d", topTimeoutInSeconds, topTimeoutInSeconds)
		topEbpfCmd := newTopEbpfCmd(cmd, false)
		RunTestSteps([]*Command{topEbpfCmd}, t)
	})
}
