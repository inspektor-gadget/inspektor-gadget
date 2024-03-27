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
	"syscall"
	"testing"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	toptcpTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/tcp/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func newTopTCPCmd(ns string, cmd string, startAndStop bool, commonDataOpts []CommonDataOption) *Command {
	validateOutputFn := func(t *testing.T, output string) {
		expectedEntry := &toptcpTypes.Stats{
			CommonData: BuildCommonData(ns, commonDataOpts...),
			Comm:       "curl",
			IPVersion:  syscall.AF_INET,
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

		if DefaultTestComponent == InspektorGadgetTestComponent {
			expectedEntry.SrcEndpoint.L3Endpoint.Kind = eventtypes.EndpointKindRaw
			expectedEntry.DstEndpoint.L3Endpoint.Kind = eventtypes.EndpointKindRaw
		}

		normalize := func(e *toptcpTypes.Stats) {
			e.MountNsID = 0
			e.Pid = 0
			e.SrcEndpoint.Port = 0
			e.Sent = 0
			e.Received = 0

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
		Name:           "TopTCP",
		ValidateOutput: validateOutputFn,
		Cmd:            cmd,
		StartAndStop:   startAndStop,
	}
}

func TestTopTcp(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-top-tcp")

	commandsPreTest := []*Command{
		CreateTestNamespaceCommand(ns),
		PodCommand("test-pod", "nginx", ns, "[sh, -c]", "nginx && while true; do curl 127.0.0.1; sleep 0.1; done"),
		WaitUntilTestPodReadyCommand(ns),
	}
	RunTestSteps(commandsPreTest, t, WithCbBeforeCleanup(PrintLogsFn(ns)))

	t.Cleanup(func() {
		commandsPostTest := []*Command{
			DeleteTestNamespaceCommand(ns),
		}
		RunTestSteps(commandsPostTest, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	commonDataOpts := []CommonDataOption{WithContainerImageName("docker.io/library/nginx:latest", isDockerRuntime)}

	var extraArgs string
	switch DefaultTestComponent {
	case IgTestComponent:
		extraArgs = "-m 999 --runtimes=" + containerRuntime
		commonDataOpts = append(commonDataOpts, WithRuntimeMetadata(containerRuntime))
	case InspektorGadgetTestComponent:
		extraArgs = "-m 100 -n " + ns
	}

	t.Run("StartAndStop", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("%s top tcp -o json %s", DefaultTestComponent, extraArgs)
		topTCPCmd := newTopTCPCmd(ns, cmd, true, commonDataOpts)
		RunTestSteps([]*Command{topTCPCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("%s top tcp -o json --timeout %d %s", DefaultTestComponent, topTimeoutInSeconds, extraArgs)
		topTCPCmd := newTopTCPCmd(ns, cmd, false, commonDataOpts)
		RunTestSteps([]*Command{topTCPCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("Interval=Timeout", func(t *testing.T) {
		t.Parallel()

		cmd := fmt.Sprintf("%s top tcp -o json --timeout %d --interval %d %s", DefaultTestComponent, topTimeoutInSeconds, topTimeoutInSeconds, extraArgs)
		topTCPCmd := newTopTCPCmd(ns, cmd, false, commonDataOpts)
		RunTestSteps([]*Command{topTCPCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})
}
