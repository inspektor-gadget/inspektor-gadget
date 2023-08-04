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

	tracemountTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/mount/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestTraceMount(t *testing.T) {
	ns := GenerateTestNamespaceName("test-trace-mount")

	t.Parallel()

	// TODO: Handle it once we support getting container image name from docker
	isDockerRuntime := IsDockerRuntime(t)

	traceMountCmd := &Command{
		Name:         "StartTraceMountGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace mount -n %s -o json", ns),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedEntry := &tracemountTypes.Event{
				Event:     BuildBaseEvent(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)),
				Comm:      "mount",
				Operation: "mount",
				Retval:    -2,
				Source:    "/mnt",
				Target:    "/mnt",
			}

			normalize := func(e *tracemountTypes.Event) {
				e.Timestamp = 0
				e.Pid = 0
				e.Tid = 0
				e.MountNsID = 0
				e.Latency = 0
				e.Fs = ""
				e.Data = ""
				e.Flags = nil
				e.FlagsRaw = 0

				e.K8s.Node = ""
				// TODO: Verify container runtime and container name
				e.Runtime.RuntimeName = ""
				e.Runtime.ContainerName = ""
				e.Runtime.ContainerID = ""
			}

			ExpectEntriesToMatch(t, output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		traceMountCmd,
		BusyboxPodRepeatCommand(ns, "mount /mnt /mnt"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
