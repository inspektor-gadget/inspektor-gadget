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
		Cmd:          fmt.Sprintf("ig trace exec -o json --runtimes=%s", *containerRuntime),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntries := []*execTypes.Event{
				{
					Event: BuildBaseEvent(ns),
					Comm:  "sh",
					Args:  shArgs,
				},
				{
					Event: BuildBaseEvent(ns),
					Comm:  "date",
					Args:  dateArgs,
					Uid:   1000,
					Gid:   1111,
				},
				{
					Event: BuildBaseEvent(ns),
					Comm:  "sleep",
					Args:  sleepArgs,
					Uid:   1000,
					Gid:   1111,
				},
			}

			normalize := func(e *execTypes.Event) {
				// TODO: Handle it once we support getting K8s container name for docker
				// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/737
				if *containerRuntime == ContainerRuntimeDocker {
					e.Container = "test-pod"
				}

				e.Timestamp = 0
				e.Pid = 0
				e.Ppid = 0
				e.LoginUid = 0
				e.SessionId = 0
				e.Retval = 0
				e.MountNsID = 0
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

func TestTraceExecHost(t *testing.T) {
	t.Parallel()

	cmd := "sh -c 'for i in $(seq 1 30); do date; /bin/sleep 0.1; done'"
	dateArgs := []string{"/usr/bin/date"}
	sleepArgs := []string{"/bin/sleep", "0.1"}

	traceExecCmd := &Command{
		Name:         "TraceExecHost",
		Cmd:          "ig trace exec -o json --host",
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
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

			return ExpectEntriesToMatch(output, normalize, expectedEntries...)
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
