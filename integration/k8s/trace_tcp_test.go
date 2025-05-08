// Copyright 2024 The Inspektor Gadget authors
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
	tracetcpTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcp/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestBuiltinTraceTCP(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-tcp")

	var extraArgs string
	expectedEntry := &tracetcpTypes.Event{
		Comm:      "curl",
		IPVersion: 4,
		Operation: "connect",
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
		extraArgs = fmt.Sprintf("--runtimes=%s", containerRuntime)
		expectedEntry.Event = BuildBaseEvent(ns,
			WithRuntimeMetadata(containerRuntime),
			WithContainerImageName("ghcr.io/inspektor-gadget/ci/nginx:latest", isDockerRuntime),
			WithPodLabels("test-pod", ns, isCrioRuntime),
		)
	case InspektorGadgetTestComponent:
		extraArgs = fmt.Sprintf("-n %s", ns)
		expectedEntry.Event = BuildBaseEventK8s(ns, WithContainerImageName("ghcr.io/inspektor-gadget/ci/nginx:latest", isDockerRuntime))
		expectedEntry.SrcEndpoint.Kind = eventtypes.EndpointKindRaw
		expectedEntry.DstEndpoint.Kind = eventtypes.EndpointKindRaw
	}

	traceTCPCmd := &Command{
		Name:         "TraceTCP",
		Cmd:          fmt.Sprintf("%s trace tcp -o json %s", DefaultTestComponent, extraArgs),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			normalize := func(e *tracetcpTypes.Event) {
				e.Timestamp = 0
				e.Pid = 0
				e.SrcEndpoint.Port = 0
				e.MountNsID = 0

				normalizeCommonData(&e.CommonData, ns)
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntry)
		},
	}

	commands := []TestStep{
		CreateTestNamespaceCommand(ns),
		traceTCPCmd,
		SleepForSecondsCommand(2), // wait to ensure ig or kubectl-gadget has started
		PodCommand("test-pod", "ghcr.io/inspektor-gadget/ci/nginx:latest", ns, "[sh, -c]", "nginx && while true; do curl 127.0.0.1; sleep 0.1; done"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
