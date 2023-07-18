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
	topfileTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/file/types"
)

func newTopFileCmd(ns, cmd string, startAndStop bool, isDockerRuntime bool) *Command {
	expectedOutputFn := func(output string) error {
		expectedEntry := &topfileTypes.Stats{
			CommonData: BuildCommonData(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)),
			Reads:      0,
			ReadBytes:  0,
			Filename:   "date.txt",
			FileType:   byte('R'), // Regular file
			Comm:       "sh",
		}

		normalize := func(e *topfileTypes.Stats) {
			e.Writes = 0
			e.WriteBytes = 0
			e.Pid = 0
			e.Tid = 0
			e.MountNsID = 0

			e.K8s.Node = ""
			// TODO: Verify container runtime and container name
			e.Runtime.RuntimeName = ""
			e.Runtime.ContainerName = ""
			e.Runtime.ContainerID = ""
		}

		return ExpectEntriesInMultipleArrayToMatch(output, normalize, expectedEntry)
	}
	return &Command{
		Name:             "TopFile",
		ExpectedOutputFn: expectedOutputFn,
		Cmd:              cmd,
		StartAndStop:     startAndStop,
	}
}

func TestTopFile(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-top-file")

	// TODO: Handle it once we support getting container image name from docker
	errIsDocker, isDockerRuntime := IsDockerRuntime()
	if errIsDocker != nil {
		t.Fatalf("checking if docker is current runtime: %v", errIsDocker)
	}

	commandsPreTest := []*Command{
		CreateTestNamespaceCommand(ns),
		BusyboxPodRepeatCommand(ns, "echo date >> /tmp/date.txt"),
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

		cmd := fmt.Sprintf("$KUBECTL_GADGET top file -n %s --sort \"-writes\" -o json", ns)
		topFileCmd := newTopFileCmd(ns, cmd, true, isDockerRuntime)
		RunTestSteps([]*Command{topFileCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("$KUBECTL_GADGET top file -n %s --sort \"-writes\" -o json --timeout %d", ns, topTimeoutInSeconds)
		topFileCmd := newTopFileCmd(ns, cmd, false, isDockerRuntime)
		RunTestSteps([]*Command{topFileCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("Interval=Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("$KUBECTL_GADGET top file -n %s --sort \"-writes\" -o json --timeout %d --interval %d", ns, topTimeoutInSeconds, topTimeoutInSeconds)
		topFileCmd := newTopFileCmd(ns, cmd, false, isDockerRuntime)
		RunTestSteps([]*Command{topFileCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})
}
