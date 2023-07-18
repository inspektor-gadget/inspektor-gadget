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
	tracetcpconnectTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcpconnect/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestTraceTcpconnect(t *testing.T) {
	ns := GenerateTestNamespaceName("test-tcpconnect")

	t.Parallel()

	// TODO: Handle it once we support getting container image name from docker
	errIsDocker, isDockerRuntime := IsDockerRuntime()
	if errIsDocker != nil {
		t.Fatalf("checking if docker is current runtime: %v", errIsDocker)
	}

	traceTcpconnectCmd := &Command{
		Name:         "StartTraceTcpconnectGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace tcpconnect -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &tracetcpconnectTypes.Event{
				Event:     BuildBaseEvent(ns, WithContainerImageName("docker.io/library/nginx:latest", isDockerRuntime)),
				Comm:      "curl",
				IPVersion: 4,
				SrcEndpoint: eventtypes.L4Endpoint{
					L3Endpoint: eventtypes.L3Endpoint{
						Addr: "127.0.0.1",
						Kind: eventtypes.EndpointKindRaw,
					},
				},
				DstEndpoint: eventtypes.L4Endpoint{
					L3Endpoint: eventtypes.L3Endpoint{
						Addr: "127.0.0.1",
						Kind: eventtypes.EndpointKindRaw,
					},
					Port: 80,
				},
			}

			normalize := func(e *tracetcpconnectTypes.Event) {
				e.Timestamp = 0
				e.Pid = 0
				e.SrcEndpoint.Port = 0
				e.MountNsID = 0

				e.K8s.Node = ""
				// TODO: Verify container runtime and container name
				e.Runtime.RuntimeName = ""
				e.Runtime.ContainerName = ""
				e.Runtime.ContainerID = ""
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		traceTcpconnectCmd,
		PodCommand("test-pod", "nginx", ns, "[sh, -c]", "nginx && while true; do curl 127.0.0.1; sleep 0.1; done"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}

func TestTraceTcpconnect_latency(t *testing.T) {
	ns := GenerateTestNamespaceName("test-tcpconnect")

	t.Parallel()

	// TODO: Handle it once we support getting container image name from docker
	errIsDocker, isDockerRuntime := IsDockerRuntime()
	if errIsDocker != nil {
		t.Fatalf("checking if docker is current runtime: %v", errIsDocker)
	}

	traceTcpconnectCmd := &Command{
		Name:         "StartTraceTcpconnectGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace tcpconnect -n %s -o json --latency", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &tracetcpconnectTypes.Event{
				Event:     BuildBaseEvent(ns, WithContainerImageName("docker.io/library/nginx:latest", isDockerRuntime)),
				Comm:      "curl",
				IPVersion: 4,
				SrcEndpoint: eventtypes.L4Endpoint{
					L3Endpoint: eventtypes.L3Endpoint{
						Addr: "127.0.0.1",
						Kind: eventtypes.EndpointKindRaw,
					},
				},
				DstEndpoint: eventtypes.L4Endpoint{
					L3Endpoint: eventtypes.L3Endpoint{
						Addr: "127.0.0.1",
						Kind: eventtypes.EndpointKindRaw,
					},
					Port: 80,
				},
				// Don't check the exact values but check that they aren't empty
				Latency: 1,
			}

			normalize := func(e *tracetcpconnectTypes.Event) {
				e.Timestamp = 0
				e.Pid = 0
				e.SrcEndpoint.Port = 0
				e.MountNsID = 0
				if e.Latency > 0 {
					e.Latency = 1
				}

				e.K8s.Node = ""
				// TODO: Verify container runtime and container name
				e.Runtime.RuntimeName = ""
				e.Runtime.ContainerName = ""
				e.Runtime.ContainerID = ""
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		traceTcpconnectCmd,
		// TODO: can't use setuidgid because it's not available on the nginx image
		PodCommand("test-pod", "nginx", ns, "[sh, -c]", "nginx && while true; do curl 127.0.0.1; sleep 0.1; done"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
