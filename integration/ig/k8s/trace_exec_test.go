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
	execTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
)

func TestTraceExec(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-exec")

	cmd := "setuidgid 1000:1111 sh -c 'while true; do date ; /bin/sleep 0.1; done'"
	shArgs := []string{"/bin/sh", "-c", cmd}
	dateArgs := []string{"/bin/date"}
	sleepArgs := []string{"/bin/sleep", "0.1"}

	traceExecCmd := &Command{
		Name:         "TraceExec",
		Cmd:          fmt.Sprintf("ig trace exec -o json --runtimes=%s", *containerRuntime),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntries := []*execTypes.Event{
				{
					Event: BuildBaseEvent(ns, WithRuntimeMetadata(*containerRuntime)),
					Comm:  "sh",
					Args:  shArgs,
				},
				{
					Event: BuildBaseEvent(ns, WithRuntimeMetadata(*containerRuntime)),
					Comm:  "date",
					Args:  dateArgs,
					Uid:   1000,
					Gid:   1111,
				},
				{
					Event: BuildBaseEvent(ns, WithRuntimeMetadata(*containerRuntime)),
					Comm:  "sleep",
					Args:  sleepArgs,
					Uid:   1000,
					Gid:   1111,
				},
			}

			normalize := func(e *execTypes.Event) {
				// Docker and CRI-O uses a custom container name composed, among
				// other things, by the pod UID. We don't know the pod UID in
				// advance, so we can't match the exact expected container name.
				prefixContainerName := "k8s_" + "test-pod" + "_" + "test-pod" + "_" + ns + "_"
				if (*containerRuntime == ContainerRuntimeDocker || *containerRuntime == ContainerRuntimeCRIO) &&
					strings.HasPrefix(e.Runtime.Container, prefixContainerName) {
					e.Runtime.Container = "test-pod"
				}

				e.Timestamp = 0
				e.Pid = 0
				e.Ppid = 0
				e.LoginUid = 0
				e.SessionId = 0
				e.Retval = 0
				e.MountNsID = 0

				e.Runtime.ContainerID = ""
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntries...)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		traceExecCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		BusyboxPodCommand(ns, cmd),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
