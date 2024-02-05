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

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	"github.com/inspektor-gadget/inspektor-gadget/integration/common"
	topebpfTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestTopEbpf(t *testing.T) {
	if *k8sDistro == K8sDistroAKSUbuntu && *k8sArch == "amd64" {
		t.Skip("Skip running top ebpf gadget on AKS Ubuntu amd64: see issue #931")
	}

	t.Parallel()

	normalizeOpts := func(e *topebpfTypes.Stats) {
		e.K8s = types.K8sMetadata{}
		// TODO: Verify container runtime and container name
		e.Runtime.RuntimeName = ""
		e.Runtime.ContainerName = ""
		e.Runtime.ContainerID = ""
		e.Runtime.ContainerImageDigest = ""
	}

	t.Run("StartAndStop", func(t *testing.T) {
		t.Parallel()

		cmd := "$KUBECTL_GADGET top ebpf -o json -m 100"
		topEbpfCmd := common.NewTopEbpfCmd(cmd, true, normalizeOpts)
		RunTestSteps([]*Command{topEbpfCmd}, t)
	})

	t.Run("Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("$KUBECTL_GADGET top ebpf -o json -m 999 --timeout %d", topTimeoutInSeconds)
		topEbpfCmd := common.NewTopEbpfCmd(cmd, false, normalizeOpts)
		RunTestSteps([]*Command{topEbpfCmd}, t)
	})

	t.Run("Interval=Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("$KUBECTL_GADGET top ebpf -o json -m 999 --timeout %d --interval %d", topTimeoutInSeconds, topTimeoutInSeconds)
		topEbpfCmd := common.NewTopEbpfCmd(cmd, false, normalizeOpts)
		RunTestSteps([]*Command{topEbpfCmd}, t)
	})
}
