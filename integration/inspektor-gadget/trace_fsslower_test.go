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

	tracefsslowerType "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/fsslower/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestTraceFsslower(t *testing.T) {
	fsType := "ext4"
	if *k8sDistro == K8sDistroARO {
		fsType = "xfs"
	}

	ns := GenerateTestNamespaceName("test-trace-fsslower")

	t.Parallel()

	fsslowerCmd := &Command{
		Name:         "StartTraceFsslowerGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace fsslower -n %s -f %s -m 0 -o json", ns, fsType),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &tracefsslowerType.Event{
				Event: BuildBaseEvent(ns),
				Comm:  "cat",
				File:  "foo",
				Op:    "R",
			}

			normalize := func(e *tracefsslowerType.Event) {
				e.Node = ""
				e.MountNsID = 0
				e.Pid = 0
				e.Bytes = 0
				e.Offset = 0
				e.Latency = 0
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		fsslowerCmd,
		BusyboxPodCommand(ns, "echo 'this is foo' > foo && while true; do cat foo && sleep 0.1; done"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}
