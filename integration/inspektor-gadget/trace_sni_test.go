// Copyright 2019-2023 The Inspektor Gadget authors
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

	tracesniTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/sni/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestTraceSni(t *testing.T) {
	ns := GenerateTestNamespaceName("test-trace-sni")

	t.Parallel()

	traceSniCmd := &Command{
		Name:         "StartTraceSniGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace sni -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &tracesniTypes.Event{
				Event: BuildBaseEvent(ns),
				Comm:  "wget",
				Name:  "inspektor-gadget.io",
				Uid:   1000,
				Gid:   1111,
			}

			normalize := func(e *tracesniTypes.Event) {
				e.Timestamp = 0
				e.MountNsID = 0
				e.NetNsID = 0
				e.Pid = 0
				e.Tid = 0

				e.K8s.Node = ""
				// TODO: Verify container runtime and container name
				e.Runtime = types.BasicRuntimeMetadata{}
			}

			return ExpectAllToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		traceSniCmd,
		BusyboxPodRepeatCommand(ns, "setuidgid 1000:1111 wget --no-check-certificate -T 2 -q -O /dev/null https://inspektor-gadget.io"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
