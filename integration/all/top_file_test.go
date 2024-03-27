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
	"strings"
	"testing"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	topfileTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/file/types"
)

func newTopFileCmd(ns, cmd string, startAndStop bool, commonDataOpts []CommonDataOption) *Command {
	validateOutputFn := func(t *testing.T, output string) {
		expectedEntry := &topfileTypes.Stats{
			CommonData: BuildCommonData(ns, commonDataOpts...),
			FileType:   byte('R'), // Regular file
			Comm:       "sh",
		}

		if DefaultTestComponent == IgTestComponent {
			expectedEntry.Filename = "bar"
		} else if DefaultTestComponent == InspektorGadgetTestComponent {
			expectedEntry.Filename = "date.txt"
			expectedEntry.Reads = 0
			expectedEntry.ReadBytes = 0
		}

		normalize := func(e *topfileTypes.Stats) {
			e.Writes = 0
			e.WriteBytes = 0
			e.Pid = 0
			e.Tid = 0
			e.MountNsID = 0

			e.Runtime.ContainerID = ""
			e.Runtime.ContainerImageDigest = ""

			if DefaultTestComponent == IgTestComponent {
				prefixContainerName := "k8s_" + "test-pod" + "_" + "test-pod" + "_" + ns + "_"
				if (containerRuntime == ContainerRuntimeDocker || containerRuntime == ContainerRuntimeCRIO) &&
					strings.HasPrefix(e.Runtime.ContainerName, prefixContainerName) {
					e.Runtime.ContainerName = "test-pod"
				}

				if isDockerRuntime {
					e.Runtime.ContainerImageName = ""
				}
			} else if DefaultTestComponent == InspektorGadgetTestComponent {
				e.K8s.Node = ""
				// TODO: Verify container runtime and container name
				e.Runtime.RuntimeName = ""
				e.Runtime.ContainerName = ""
			}
		}

		ExpectEntriesInMultipleArrayToMatch(t, output, normalize, expectedEntry)
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

	commonDataOpts := []CommonDataOption{WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)}

	var extraArgs string
	var busyboxCmd string
	switch DefaultTestComponent {
	case IgTestComponent:
		extraArgs = "--sort -writes,-wbytes -m 999 --runtimes=" + containerRuntime
		commonDataOpts = append(commonDataOpts, WithRuntimeMetadata(containerRuntime))
		busyboxCmd = "echo foo > bar"
	case InspektorGadgetTestComponent:
		extraArgs = "--sort \"-writes\" -n " + ns
		busyboxCmd = "echo date >> /tmp/date.txt"
	}

	commandsPreTest := []*Command{
		CreateTestNamespaceCommand(ns),
		BusyboxPodRepeatCommand(ns, busyboxCmd),
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

		cmd := fmt.Sprintf("%s top file -o json %s", DefaultTestComponent, extraArgs)
		topFileCmd := newTopFileCmd(ns, cmd, true, commonDataOpts)
		RunTestSteps([]*Command{topFileCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("%s top file -o json --timeout %d %s", DefaultTestComponent, topTimeoutInSeconds, extraArgs)
		topFileCmd := newTopFileCmd(ns, cmd, false, commonDataOpts)
		RunTestSteps([]*Command{topFileCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("Interval=Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("%s top file -o json --timeout %d --interval %d %s", DefaultTestComponent, topTimeoutInSeconds, topTimeoutInSeconds, extraArgs)
		topFileCmd := newTopFileCmd(ns, cmd, false, commonDataOpts)
		RunTestSteps([]*Command{topFileCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})
}
