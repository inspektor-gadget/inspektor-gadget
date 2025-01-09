// Copyright 2024 The Inspektor Gadget authors
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
	traceexecTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestTraceExec(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-exec")

	innerCmd := "while true ; do /bin/sleep 0.1 ; done"
	cmd := fmt.Sprintf("cp /bin/sh /usr/bin/sh ; setuidgid 1000:1111 /usr/bin/sh -c '%s'", innerCmd)
	shArgs := []string{"/bin/sh", "-c", cmd}
	innerShArgs := []string{"/usr/bin/sh", "-c", innerCmd}
	sleepArgs := []string{"/bin/sleep", "0.1"}

	var extraArgs string
	var expectedEvent eventtypes.Event
	switch DefaultTestComponent {
	case IgTestComponent:
		extraArgs = fmt.Sprintf("--runtimes=%s", containerRuntime)
		expectedEvent = BuildBaseEvent(ns,
			WithRuntimeMetadata(containerRuntime),
			WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime),
			WithPodLabels("test-pod", ns, isCrioRuntime),
		)
	case InspektorGadgetTestComponent:
		extraArgs = fmt.Sprintf("-n %s", ns)
		expectedEvent = BuildBaseEventK8s(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime))
	}

	traceExecCmd := &Command{
		Name:         "TraceExec",
		Cmd:          fmt.Sprintf("%s trace exec --paths -o json %s", DefaultTestComponent, extraArgs),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedEntries := []*traceexecTypes.Event{
				{
					Event:   expectedEvent,
					Comm:    "sh",
					Pcomm:   "", // Not tested, see normalize()
					Args:    shArgs,
					Cwd:     "/",
					ExePath: "/bin/sh",
					File:    "/bin/sh",
				},
				{
					Event:      expectedEvent,
					Comm:       "sh",
					Pcomm:      "", // Not tested, see normalize()
					Args:       innerShArgs,
					Uid:        1000,
					Gid:        1111,
					Cwd:        "/",
					ExePath:    "/usr/bin/sh",
					File:       "/usr/bin/sh",
					UpperLayer: true,
				},
				{
					Event:       expectedEvent,
					Comm:        "sleep",
					Pcomm:       "sh",
					Args:        sleepArgs,
					Uid:         1000,
					Gid:         1111,
					Cwd:         "/",
					ExePath:     "/bin/sleep",
					File:        "/bin/sleep",
					PupperLayer: true,
				},
			}

			normalize := func(e *traceexecTypes.Event) {
				e.Timestamp = 0
				e.Pid = 0
				e.Tid = 0
				e.Ppid = 0
				e.Ptid = 0
				e.LoginUid = 0
				e.SessionId = 0
				e.Retval = 0
				e.MountNsID = 0
				e.Username = ""
				e.Groupname = ""

				if e.Comm == "sh" {
					// Not tested because it varies depending on container runtime:
					// - containerd: "containerd-shim"
					e.Pcomm = ""
				}

				normalizeCommonData(&e.CommonData, ns)
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntries...)
		},
	}

	commands := []TestStep{
		CreateTestNamespaceCommand(ns),
		traceExecCmd,
		SleepForSecondsCommand(3), // wait to ensure ig or kubectl-gadget has started
		BusyboxPodCommand(ns, cmd),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}

func TestTraceExecHost(t *testing.T) {
	if DefaultTestComponent != IgTestComponent {
		t.Skip("Skip running trace exec host with test component different than ig")
	}

	t.Parallel()

	cmd := "sh -c 'for i in $(seq 1 30); do date; /bin/sleep 0.1; done'"
	dateArgs := []string{"/usr/bin/date"}
	sleepArgs := []string{"/bin/sleep", "0.1"}

	traceExecCmd := &Command{
		Name:         "TraceExecHost",
		Cmd:          "ig trace exec -o json --host",
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedEntries := []*traceexecTypes.Event{
				{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					Comm:  "date",
					Pcomm: "sh",
					Args:  dateArgs,
				},
				{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					Comm:  "sleep",
					Pcomm: "sh",
					Args:  sleepArgs,
				},
			}

			normalize := func(e *traceexecTypes.Event) {
				e.Timestamp = 0
				e.Pid = 0
				e.Tid = 0
				e.Ppid = 0
				e.Ptid = 0
				e.LoginUid = 0
				e.SessionId = 0
				e.Retval = 0
				e.MountNsID = 0
				e.Username = ""
				e.Groupname = ""
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntries...)
		},
	}

	commands := []TestStep{
		traceExecCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		&Command{
			Name:           cmd,
			Cmd:            cmd,
			ExpectedRegexp: fmt.Sprintf("%d", time.Now().Year()),
		},
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(func(t *testing.T) {}))
}
