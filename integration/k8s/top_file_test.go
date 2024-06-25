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
	topfileTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/file/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
)

func newTopFileCmd(ns string, cmd string, startAndStop bool, expectedEntry *topfileTypes.Stats) *Command {
	validateOutputFn := func(t *testing.T, output string) {
		normalize := func(e *topfileTypes.Stats) {
			e.Pid = 0
			e.Tid = 0
			e.MountNsID = 0
			e.Writes = 0
			e.WriteBytes = 0

			normalizeCommonData(&e.CommonData, ns)
		}

		match.MatchEntries(t, match.JSONMultiArrayMode, output, normalize, expectedEntry)
	}

	return &Command{
		Name:           "TopFile",
		ValidateOutput: validateOutputFn,
		Cmd:            cmd,
		StartAndStop:   startAndStop,
	}
}

func TestTopFile(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-top-file")

	var extraArgs string
	expectedEntry := &topfileTypes.Stats{
		// echo is built-in
		Comm:      "sh",
		FileType:  'R',
		Reads:     0,
		ReadBytes: 0,
		Filename:  "bar",
	}

	switch DefaultTestComponent {
	case IgTestComponent:
		// TODO: Filter by namespace to avoid interferences with events from other
		// tests. In the meanwhile, given that we are generating events by writing
		// into a file:
		// 	(1) Increase max-rows to 999 (default is 20)
		// 	(2) Sort by "-writes,-wbytes" (default is "-reads,-writes,-rbytes,-wbytes")
		extraArgs = fmt.Sprintf("--sort -writes,-wbytes -m %d --runtimes=%s", maxRows, containerRuntime)
		expectedEntry.CommonData = BuildCommonData(ns,
			WithRuntimeMetadata(containerRuntime),
			WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime),
			WithPodLabels("test-pod", ns, isCrioRuntime),
		)
	case InspektorGadgetTestComponent:
		extraArgs = fmt.Sprintf("--sort \"-writes\" -n %s", ns)
		expectedEntry.CommonData = BuildCommonDataK8s(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime))
	}

	commandsPreTest := []TestStep{
		CreateTestNamespaceCommand(ns),
		BusyboxPodRepeatCommand(ns, "echo foo > bar"),
		WaitUntilTestPodReadyCommand(ns),
	}
	RunTestSteps(commandsPreTest, t, WithCbBeforeCleanup(PrintLogsFn(ns)))

	t.Cleanup(func() {
		commandsPostTest := []TestStep{
			DeleteTestNamespaceCommand(ns),
		}
		RunTestSteps(commandsPostTest, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("StartAndStop", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("%s top file -o json %s", DefaultTestComponent, extraArgs)
		topFileCmd := newTopFileCmd(ns, cmd, true, expectedEntry)
		RunTestSteps([]TestStep{topFileCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("%s top file -o json --timeout %d %s",
			DefaultTestComponent, timeout, extraArgs)
		topFileCmd := newTopFileCmd(ns, cmd, false, expectedEntry)
		RunTestSteps([]TestStep{topFileCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("Interval=Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("%s top file -o json --timeout %d --interval %d %s",
			DefaultTestComponent, timeout, timeout, extraArgs)
		topFileCmd := newTopFileCmd(ns, cmd, false, expectedEntry)
		RunTestSteps([]TestStep{topFileCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})
}
