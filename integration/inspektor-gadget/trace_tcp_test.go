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

	tracetcpTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcp/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestTraceTcp(t *testing.T) {
	ns := GenerateTestNamespaceName("test-trace-tcp")

	t.Parallel()

	// TODO: Handle it once we support getting container image name from docker
	errIsDocker, isDockerRuntime := IsDockerRuntime()
	if errIsDocker != nil {
		t.Fatalf("checking if docker is current runtime: %v", errIsDocker)
	}

	traceTCPCmd := &Command{
		Name:         "StartTraceTcpGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace tcp -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &tracetcpTypes.Event{
				Event:     BuildBaseEvent(ns, WithContainerImageName("docker.io/library/nginx:latest", isDockerRuntime)),
				Comm:      "curl",
				IPVersion: 4,
				Operation: "connect",
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

			normalize := func(e *tracetcpTypes.Event) {
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

			fmt.Printf("output: %s\n", output)

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		traceTCPCmd,
		// TODO: can't use setuidgid because it's not available on the nginx image
		PodCommand("test-pod", "nginx", ns, "[sh, -c]", "nginx && while true; do curl 127.0.0.1; sleep 0.1; done"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
