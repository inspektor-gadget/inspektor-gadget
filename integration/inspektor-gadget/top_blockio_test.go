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

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	topblockioTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/block-io/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func newTopBlockIOCmd(ns string, cmd string, startAndStop bool) *Command {
	expectedOutputFn := func(output string) error {
		expectedEntry := &topblockioTypes.Stats{
			CommonData: BuildCommonData(ns),
			Write:      true,
			Comm:       "dd",
		}

		normalize := func(e *topblockioTypes.Stats) {
			e.Major = 0
			e.Minor = 0
			e.MicroSecs = 0
			e.MountNsID = 0
			e.Pid = 0
			e.Operations = 0
			e.Bytes = 0

			e.K8s.Node = ""
			// TODO: Verify container runtime and container name
			e.Runtime = types.BasicRuntimeMetadata{}
		}

		return ExpectEntriesInMultipleArrayToMatch(output, normalize, expectedEntry)
	}
	return &Command{
		Name:             "TopBlockIO",
		ExpectedOutputFn: expectedOutputFn,
		Cmd:              cmd,
		StartAndStop:     startAndStop,
	}
}

func TestTopBlockIO(t *testing.T) {
	if *k8sDistro == K8sDistroARO {
		t.Skip("Skip running top block-io gadget on ARO: see issue #589")
	}

	t.Parallel()
	ns := GenerateTestNamespaceName("test-top-block-io")

	commandsPreTest := []*Command{
		CreateTestNamespaceCommand(ns),
		BusyboxPodRepeatCommand(ns, "dd if=/dev/zero of=/tmp/test count=4096"),
		WaitUntilTestPodReadyCommand(ns),
	}
	RunTestSteps(commandsPreTest, t, WithCbBeforeCleanup(PrintLogsFn(ns)))

	t.Cleanup(func() {
		commandsPostTest := []*Command{
			DeleteTestNamespaceCommand(ns),
		}
		RunTestSteps(commandsPostTest, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("StartAndStop", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("$KUBECTL_GADGET top block-io -n %s -o json", ns)
		topBlockIOCmd := newTopBlockIOCmd(ns, cmd, true)
		RunTestSteps([]*Command{topBlockIOCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("$KUBECTL_GADGET top block-io -n %s -o json --timeout %d", ns, topTimeoutInSeconds)
		topBlockIOCmd := newTopBlockIOCmd(ns, cmd, false)
		RunTestSteps([]*Command{topBlockIOCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("Interval=Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("$KUBECTL_GADGET top block-io -n %s -o json --timeout %d --interval %d", ns, topTimeoutInSeconds, topTimeoutInSeconds)
		topBlockIOCmd := newTopBlockIOCmd(ns, cmd, false)
		RunTestSteps([]*Command{topBlockIOCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})
}
