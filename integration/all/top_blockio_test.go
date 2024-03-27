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
	"strings"
	"testing"

	"github.com/moby/moby/pkg/parsers/kernel"
	"github.com/stretchr/testify/require"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	topblockioTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/block-io/types"
)

func newTopBlockIOCmd(ns string, cmd string, startAndStop bool, commonDataOpts []CommonDataOption) *Command {
	validateOutputFn := func(t *testing.T, output string) {
		expectedEntry := &topblockioTypes.Stats{
			CommonData: BuildCommonData(ns, commonDataOpts...),
			Comm:       "dd",
			Write:      true,
		}

		normalize := func(e *topblockioTypes.Stats) {

			e.Pid = 0
			e.MountNsID = 0
			e.Major = 0
			e.Minor = 0
			e.Bytes = 0
			e.MicroSecs = 0
			e.Operations = 0

			e.Runtime.ContainerID = ""
			e.Runtime.ContainerImageDigest = ""

			if DefaultTestComponent == IgTestComponent {
				// Docker and CRI-O use a custom container name composed, among
				// other things, by the pod UID. We don't know the pod UID in
				// advance, so we can't match the exact expected container name.
				prefixContainerName := "k8s_" + "test-pod" + "_" + "test-pod" + "_" + ns + "_"
				if (containerRuntime == ContainerRuntimeDocker || containerRuntime == ContainerRuntimeCRIO) &&
					strings.HasPrefix(e.Runtime.ContainerName, prefixContainerName) {
					e.Runtime.ContainerName = "test-pod"
				}
				// Docker can provide different values for ContainerImageName. See `getContainerImageNamefromImage`
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
		Name:           "TopBlockIO",
		ValidateOutput: validateOutputFn,
		Cmd:            cmd,
		StartAndStop:   startAndStop,
	}
}

func TestTopBlockIO(t *testing.T) {
	if *k8sDistro == K8sDistroARO {
		t.Skip("Skip running top block-io gadget on ARO: see issue #589")
	}

	version, err := kernel.GetKernelVersion()
	require.Nil(t, err, "Failed to get kernel version: %s", err)
	v5_17 := kernel.VersionInfo{Kernel: 5, Major: 17, Minor: 0}
	if kernel.CompareKernelVersion(*version, v5_17) >= 0 {
		t.Skip("Skip running top block-io on kernels 5.17+. See issue #2029")
	}

	t.Parallel()
	ns := GenerateTestNamespaceName("test-top-block-io")
	commonDataOpts := []CommonDataOption{WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)}

	var extraArgs string
	switch DefaultTestComponent {
	case IgTestComponent:
		extraArgs = "--runtimes=" + containerRuntime + " -m 999"
		commonDataOpts = append(commonDataOpts, WithRuntimeMetadata(containerRuntime))
	case InspektorGadgetTestComponent:
		extraArgs = "-n " + ns
	}

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

		cmd := fmt.Sprintf("%s top block-io -o json  %s", DefaultTestComponent, extraArgs)
		topBlockIOCmd := newTopBlockIOCmd(ns, cmd, true, commonDataOpts)
		RunTestSteps([]*Command{topBlockIOCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("%s top block-io -o json --timeout %d %s",
			DefaultTestComponent, timeout, extraArgs)
		topBlockIOCmd := newTopBlockIOCmd(ns, cmd, false, commonDataOpts)
		RunTestSteps([]*Command{topBlockIOCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("Interval=Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("%s top block-io -o json --timeout %d --interval %d %s",
			DefaultTestComponent, timeout, timeout, extraArgs)
		topBlockIOCmd := newTopBlockIOCmd(ns, cmd, false, commonDataOpts)
		RunTestSteps([]*Command{topBlockIOCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})
}
