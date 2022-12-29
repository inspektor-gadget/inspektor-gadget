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
	"testing"

	"golang.org/x/sys/unix"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	mountTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/mount/types"
)

func TestTraceMount(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-mount")

	traceMountCmd := &Command{
		Name:         "TraceMount",
		Cmd:          fmt.Sprintf("local-gadget trace mount -o json --runtimes=%s", *containerRuntime),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &mountTypes.Event{
				Event:     BuildBaseEvent(ns),
				Comm:      "mount",
				Operation: "mount",
				Retval:    -int(unix.ENOENT),
				Source:    "/mnt",
				Target:    "/mnt",
				Flags:     []string{"MS_SILENT"},
			}

			normalize := func(e *mountTypes.Event) {
				// TODO: Handle it once we support getting K8s container name for docker
				// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/737
				if *containerRuntime == ContainerRuntimeDocker {
					e.Container = "test-pod"
				}

				e.Pid = 0
				e.Tid = 0
				e.MountNsID = 0
				e.Latency = 0
				e.Fs = ""
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		traceMountCmd,
		SleepForSecondsCommand(2), // wait to ensure local-gadget has started
		BusyboxPodRepeatCommand(ns, "mount /mnt /mnt"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}
