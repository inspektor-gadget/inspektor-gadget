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
	tracetcpTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcp/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestTraceTcp(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-tcp")

	commonDataOpts := []CommonDataOption{WithContainerImageName("docker.io/library/nginx:latest", isDockerRuntime)}

	var extraArgs string
	switch DefaultTestComponent {
	case IgTestComponent:
		extraArgs = "--runtimes=" + containerRuntime
		commonDataOpts = append(commonDataOpts, WithRuntimeMetadata(containerRuntime))
	case InspektorGadgetTestComponent:
		extraArgs = "-n " + ns
	}

	traceTCPCmd := &Command{
		Name:         "StartTraceTcpGadget",
		Cmd:          fmt.Sprintf("%s trace tcp -o json %s", DefaultTestComponent, extraArgs),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedEntry := &tracetcpTypes.Event{
				Event:     BuildBaseEvent(ns, commonDataOpts...),
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

			if DefaultTestComponent == InspektorGadgetTestComponent {
				expectedEntry.SrcEndpoint.L3Endpoint.Kind = eventtypes.EndpointKindRaw
				expectedEntry.DstEndpoint.L3Endpoint.Kind = eventtypes.EndpointKindRaw
			}

			normalize := func(e *tracetcpTypes.Event) {
				e.Timestamp = 0
				e.Pid = 0
				e.SrcEndpoint.Port = 0
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

			fmt.Printf("output: %s\n", output)

			ExpectEntriesToMatch(t, output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		traceTCPCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		// TODO: can't use setuidgid because it's not available on the nginx image
		PodCommand("test-pod", "nginx", ns, "[sh, -c]", "nginx && while true; do curl 127.0.0.1; sleep 0.1; done"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
