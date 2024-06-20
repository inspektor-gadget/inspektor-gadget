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

	"github.com/moby/moby/pkg/parsers/kernel"
	"github.com/stretchr/testify/require"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	topblockioTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/block-io/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
)

func newTopBlockIOCmd(ns string, cmd string, startAndStop bool, expectedEntry *topblockioTypes.Stats) *Command {
	validateOutputFn := func(t *testing.T, output string) {
		normalize := func(e *topblockioTypes.Stats) {
			e.Pid = 0
			e.MountNsID = 0
			e.Major = 0
			e.Minor = 0
			e.Bytes = 0
			e.MicroSecs = 0
			e.Operations = 0

			normalizeCommonData(&e.CommonData, ns)
		}

		match.MatchEntries(t, match.JSONMultiArrayMode, output, normalize, expectedEntry)
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

	if *k8sDistro == K8sDistroEKSAmazonLinux {
		t.Skip("Skip running top block-io gadget on EKS: see issue #589")
	}

	version, err := kernel.GetKernelVersion()
	require.Nil(t, err, "Failed to get kernel version: %s", err)
	v5_17 := kernel.VersionInfo{Kernel: 5, Major: 17, Minor: 0}
	if kernel.CompareKernelVersion(*version, v5_17) >= 0 {
		t.Skip("Skip running top block-io on kernels 5.17+. See issue #2029")
	}

	t.Parallel()
	ns := GenerateTestNamespaceName("test-top-block-io")

	var extraArgs string
	expectedEntry := &topblockioTypes.Stats{
		Comm:  "dd",
		Write: true,
	}

	switch DefaultTestComponent {
	case IgTestComponent:
		// TODO: Filter by namespace to avoid interferences with events from other
		// tests. In the meanwhile, given that we are generating events by writing
		// into a file:
		// 	(1) Increase max-rows to 999 (default is 20)
		extraArgs = fmt.Sprintf("--runtimes=%s -m %d", containerRuntime, maxRows)
		expectedEntry.CommonData = BuildCommonData(ns,
			WithRuntimeMetadata(containerRuntime),
			WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime),
			WithPodLabels("test-pod", ns, isCrioRuntime),
		)
	case InspektorGadgetTestComponent:
		extraArgs = fmt.Sprintf("-n %s", ns)
		expectedEntry.CommonData = BuildCommonDataK8s(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime))
	}

	commandsPreTest := []TestStep{
		CreateTestNamespaceCommand(ns),
		// Adding an additional sleep time to generate less events and avoid
		// interference with other tests. See TestTopFile for more details.
		BusyboxPodRepeatCommand(ns, "dd if=/dev/zero of=/tmp/test count=4096; sleep 0.2"),
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

		cmd := fmt.Sprintf("%s top block-io -o json %s", DefaultTestComponent, extraArgs)
		topBlockIOCmd := newTopBlockIOCmd(ns, cmd, true, expectedEntry)
		RunTestSteps([]TestStep{topBlockIOCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("%s top block-io -o json --timeout %d %s",
			DefaultTestComponent, topTimeoutInSeconds, extraArgs)
		topBlockIOCmd := newTopBlockIOCmd(ns, cmd, false, expectedEntry)
		RunTestSteps([]TestStep{topBlockIOCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("Interval=Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("%s top block-io -o json --timeout %d --interval %d %s",
			DefaultTestComponent, topTimeoutInSeconds, topTimeoutInSeconds, extraArgs)
		topBlockIOCmd := newTopBlockIOCmd(ns, cmd, false, expectedEntry)
		RunTestSteps([]TestStep{topBlockIOCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})
}
