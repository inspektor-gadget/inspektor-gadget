// Copyright 2022 The Inspektor Gadget authors
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
	"strings"
	"testing"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	openTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
)

func TestTraceOpen(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-open")

	traceOpenCmd := &Command{
		Name:         "TraceOpen",
		Cmd:          fmt.Sprintf("ig trace open -o json --runtimes=%s", *containerRuntime),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			isDockerRuntime := *containerRuntime == ContainerRuntimeDocker
			expectedEntry := &openTypes.Event{
				Event: BuildBaseEvent(ns,
					WithRuntimeMetadata(*containerRuntime),
					WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime),
				),
				Comm:     "cat",
				Fd:       3,
				Ret:      3,
				Err:      0,
				Path:     "/dev/null",
				FullPath: "",
				Uid:      1000,
				Gid:      1111,
				Flags:    []string{"O_RDONLY"},
				Mode:     "----------",
			}

			normalize := func(e *openTypes.Event) {
				// Docker and CRI-O use a custom container name composed, among
				// other things, by the pod UID. We don't know the pod UID in
				// advance, so we can't match the exact expected container name.
				prefixContainerName := "k8s_" + "test-pod" + "_" + "test-pod" + "_" + ns + "_"
				if (*containerRuntime == ContainerRuntimeDocker || *containerRuntime == ContainerRuntimeCRIO) &&
					strings.HasPrefix(e.Runtime.ContainerName, prefixContainerName) {
					e.Runtime.ContainerName = "test-pod"
				}

				e.Timestamp = 0
				e.MountNsID = 0
				e.Pid = 0

				e.Runtime.ContainerID = ""
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		traceOpenCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		BusyboxPodRepeatCommand(ns, "setuidgid 1000:1111 cat /dev/null"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
