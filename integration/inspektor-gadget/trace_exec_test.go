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

	traceexecTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestTraceExec(t *testing.T) {
	ns := GenerateTestNamespaceName("test-trace-exec")

	t.Parallel()

	cmd := "while true; do date ; /bin/sleep 0.1; done"
	shArgs := []string{"/bin/sh", "-c", cmd}
	dateArgs := []string{"/bin/date"}
	sleepArgs := []string{"/bin/sleep", "0.1"}
	// on arm64, trace exec uses kprobe and it cannot trace the arguments:
	// 243759db6b19 ("pkg/gadgets: Use kprobe for execsnoop on arm64.")
	if *k8sArch == "arm64" {
		shArgs = nil
		dateArgs = nil
		sleepArgs = nil
	}

	traceExecCmd := &Command{
		Name:         "StartTraceExecGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace exec -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntries := []*traceexecTypes.Event{
				{
					Event: BuildBaseEvent(ns),
					Comm:  "sh",
					Args:  shArgs,
				},
				{
					Event: BuildBaseEvent(ns),
					Comm:  "date",
					Args:  dateArgs,
				},
				{
					Event: BuildBaseEvent(ns),
					Comm:  "sleep",
					Args:  sleepArgs,
				},
			}

			normalize := func(e *traceexecTypes.Event) {
				e.Timestamp = 0
				e.Node = ""
				e.Pid = 0
				e.Ppid = 0
				e.UID = 0
				e.Retval = 0
				e.MountNsID = 0
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntries...)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		traceExecCmd,
		// Give time to kubectl-gadget to start the tracer
		SleepForSecondsCommand(3),
		BusyboxPodCommand(ns, cmd),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
