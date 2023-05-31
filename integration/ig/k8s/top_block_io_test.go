// Copyright 2022-2023 The Inspektor Gadget authors
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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/block-io/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func newTopBlockIOCmd(ns string, cmd string, startAndStop bool) *Command {
	expectedOutputFn := func(output string) error {
		expectedEntry := &types.Stats{
			CommonData: eventtypes.CommonData{
				K8s: eventtypes.K8sMetadata{
					BasicK8sMetadata: eventtypes.BasicK8sMetadata{
						Namespace: ns,
						PodName:   "test-pod",
					},
				},
			},
			Comm:  "dd",
			Write: true,
		}

		normalize := func(e *types.Stats) {
			e.K8s.ContainerName = ""
			e.Pid = 0
			e.MountNsID = 0
			e.Major = 0
			e.Minor = 0
			e.Bytes = 0
			e.MicroSecs = 0
			e.Operations = 0
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
	t.Parallel()
	ns := GenerateTestNamespaceName("test-top-block-io")

	commandsPreTest := []*Command{
		CreateTestNamespaceCommand(ns),
		// Adding an additional sleep time to generate less events and avoid
		// interference with other tests. See TestTopFile for more details.
		BusyboxPodRepeatCommand(ns, "dd if=/dev/zero of=/tmp/test count=4096; sleep 0.2"),
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

		cmd := fmt.Sprintf("ig top block-io -o json -m 999 --runtimes=%s", *containerRuntime)
		topBlockIOCmd := newTopBlockIOCmd(ns, cmd, true)
		RunTestSteps([]*Command{topBlockIOCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("ig top block-io -o json -m 999 --runtimes=%s --timeout %d",
			*containerRuntime, timeout)
		topBlockIOCmd := newTopBlockIOCmd(ns, cmd, false)
		RunTestSteps([]*Command{topBlockIOCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("Interval=Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("ig top block-io -o json -m 999 --runtimes=%s --timeout %d --interval %d",
			*containerRuntime, timeout, timeout)
		topBlockIOCmd := newTopBlockIOCmd(ns, cmd, false)
		RunTestSteps([]*Command{topBlockIOCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})
}
