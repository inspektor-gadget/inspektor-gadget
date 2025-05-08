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
	toptcpTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/tcp/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func newTopTCPCmd(ns string, cmd string, startAndStop bool, expectedEntry *toptcpTypes.Stats) *Command {
	validateOutputFn := func(t *testing.T, output string) {
		normalize := func(e *toptcpTypes.Stats) {
			e.Pid = 0
			e.MountNsID = 0
			e.SrcEndpoint.Port = 0
			e.Sent = 0
			e.Received = 0

			normalizeCommonData(&e.CommonData, ns)
		}

		match.MatchEntries(t, match.JSONMultiArrayMode, output, normalize, expectedEntry)
	}

	return &Command{
		Name:           "TopTCP",
		ValidateOutput: validateOutputFn,
		Cmd:            cmd,
		StartAndStop:   startAndStop,
	}
}

func TestBuiltinTopTCP(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-top-tcp")

	commandsPreTest := []TestStep{
		CreateTestNamespaceCommand(ns),
		PodCommand("test-pod", "ghcr.io/inspektor-gadget/ci/nginx:latest", ns, "[sh, -c]", "nginx && while true; do curl 127.0.0.1; sleep 0.1; done"),
		WaitUntilTestPodReadyCommand(ns),
	}
	RunTestSteps(commandsPreTest, t, WithCbBeforeCleanup(PrintLogsFn(ns)))

	t.Cleanup(func() {
		commandsPostTest := []TestStep{
			DeleteTestNamespaceCommand(ns),
		}
		RunTestSteps(commandsPostTest, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	var extraArgs string
	expectedEntry := &toptcpTypes.Stats{
		Comm:      "curl",
		IPVersion: 4,
		SrcEndpoint: eventtypes.L4Endpoint{
			L3Endpoint: eventtypes.L3Endpoint{
				Addr:    "127.0.0.1",
				Version: 4,
			},
		},
		DstEndpoint: eventtypes.L4Endpoint{
			L3Endpoint: eventtypes.L3Endpoint{
				Addr:    "127.0.0.1",
				Version: 4,
			},
			Port: 80,
		},
	}

	switch DefaultTestComponent {
	case IgTestComponent:
		extraArgs = fmt.Sprintf("-m %d --runtimes=%s", maxRows, containerRuntime)
		expectedEntry.CommonData = BuildCommonData(ns,
			WithRuntimeMetadata(containerRuntime),
			WithContainerImageName("ghcr.io/inspektor-gadget/ci/nginx:latest", isDockerRuntime),
			WithPodLabels("test-pod", ns, isCrioRuntime),
		)
	case InspektorGadgetTestComponent:
		extraArgs = fmt.Sprintf("-m 100 -n %s", ns)
		expectedEntry.CommonData = BuildCommonDataK8s(ns, WithContainerImageName("ghcr.io/inspektor-gadget/ci/nginx:latest", isDockerRuntime))
		expectedEntry.SrcEndpoint.Kind = eventtypes.EndpointKindRaw
		expectedEntry.DstEndpoint.Kind = eventtypes.EndpointKindRaw
	}

	t.Run("StartAndStop", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("%s top tcp -o json %s", DefaultTestComponent, extraArgs)
		topTCPCmd := newTopTCPCmd(ns, cmd, true, expectedEntry)
		RunTestSteps([]TestStep{topTCPCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("%s top tcp -o json --timeout %d %s",
			DefaultTestComponent, timeout, extraArgs)
		topTCPCmd := newTopTCPCmd(ns, cmd, false, expectedEntry)
		RunTestSteps([]TestStep{topTCPCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("Interval=Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("%s top tcp -o json --timeout %d --interval %d %s",
			DefaultTestComponent, timeout, timeout, extraArgs)
		topTCPCmd := newTopTCPCmd(ns, cmd, false, expectedEntry)
		RunTestSteps([]TestStep{topTCPCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})
}
