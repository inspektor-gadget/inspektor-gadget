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
	"time"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	execTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
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
		Cmd:          fmt.Sprintf("ig trace exec -o json --runtimes=%s --cwd", *containerRuntime),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			isDockerRuntime := *containerRuntime == ContainerRuntimeDocker
			expectedEntries := []*execTypes.Event{
				{
					Event: BuildBaseEvent(ns,
						WithRuntimeMetadata(*containerRuntime),
						WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime),
					),
					Comm: "sh",
					Args: shArgs,
					Cwd:  "/",
				},
				{
					Event: BuildBaseEvent(ns,
						WithRuntimeMetadata(*containerRuntime),
						WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime),
					),
					Comm: "date",
					Args: dateArgs,
					Uid:  1000,
					Gid:  1111,
					Cwd:  "/",
				},
				{
					Event: BuildBaseEvent(ns,
						WithRuntimeMetadata(*containerRuntime),
						WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime),
					),
					Comm: "sleep",
					Args: sleepArgs,
					Uid:  1000,
					Gid:  1111,
					Cwd:  "/",
				},
			}

			normalize := func(e *execTypes.Event) {
				// Docker and CRI-O use a custom container name composed, among
				// other things, by the pod UID. We don't know the pod UID in
				// advance, so we can't match the exact expected container name.
				prefixContainerName := "k8s_" + "test-pod" + "_" + "test-pod" + "_" + ns + "_"
				if (*containerRuntime == ContainerRuntimeDocker || *containerRuntime == ContainerRuntimeCRIO) &&
					strings.HasPrefix(e.Runtime.ContainerName, prefixContainerName) {
					e.Runtime.ContainerName = "test-pod"
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

			ExpectEntriesToMatch(t, output, normalize, expectedEntries...)
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

func TestTraceExecHost(t *testing.T) {
	t.Parallel()

	cmd := "sh -c 'for i in $(seq 1 30); do date; /bin/sleep 0.1; done'"
	dateArgs := []string{"/usr/bin/date"}
	sleepArgs := []string{"/bin/sleep", "0.1"}

	traceExecCmd := &Command{
		Name:         "TraceExecHost",
		Cmd:          "ig trace exec -o json --host",
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedEntries := []*execTypes.Event{
				{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					Comm: "date",
					Args: dateArgs,
				},
				{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					Comm: "sleep",
					Args: sleepArgs,
				},
			}

			normalize := func(e *execTypes.Event) {
				e.Timestamp = 0
				e.Pid = 0
				e.Ppid = 0
				e.LoginUid = 0
				e.SessionId = 0
				e.Retval = 0
				e.MountNsID = 0
			}

			ExpectEntriesToMatch(t, output, normalize, expectedEntries...)
		},
	}

	commands := []*Command{
		traceExecCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		{
			Name:           cmd,
			Cmd:            cmd,
			ExpectedRegexp: fmt.Sprintf("%d", time.Now().Year()),
		},
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(func(t *testing.T) {}))
}
