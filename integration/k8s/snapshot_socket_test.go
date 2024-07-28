// Copyright 2019-2023 The Inspektor Gadget authors
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
	snapshotsocketTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/socket/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestSnapshotSocket(t *testing.T) {
	if DefaultTestComponent != InspektorGadgetTestComponent {
		t.Skip("Skip running test with test component different than kubectl-gadget")
	}

	if *k8sDistro == K8sDistroARO {
		t.Skip("Skip running snapshot socket gadget on ARO: iterators are not supported on kernel 4.18.0-305.19.1.el8_4.x86_64")
	}

	ns := GenerateTestNamespaceName("test-socket-collector")

	t.Parallel()

	commandsPreTest := []TestStep{
		CreateTestNamespaceCommand(ns),
		BusyboxPodCommand(ns, "nc -l 0.0.0.0 -p 9090"),
		WaitUntilTestPodReadyCommand(ns),
	}
	RunTestSteps(commandsPreTest, t, WithCbBeforeCleanup(PrintLogsFn(ns)))

	t.Cleanup(func() {
		commandsPostTest := []TestStep{
			DeleteTestNamespaceCommand(ns),
		}
		RunTestSteps(commandsPostTest, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	nodeName := GetPodNode(t, ns, "test-pod")

	t.Log("Node name:", nodeName)

	commands := []TestStep{
		&Command{
			Name: "RunSnapshotSocketGadget",
			Cmd:  fmt.Sprintf("$KUBECTL_GADGET snapshot socket -n %s -o json --node %s", ns, nodeName),
			ValidateOutput: func(t *testing.T, output string) {
				t.Log("Output:", output)

				expectedEntry := &snapshotsocketTypes.Event{
					Event:    BuildBaseEventK8s(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)),
					Protocol: "TCP",
					SrcEndpoint: eventtypes.L4Endpoint{
						L3Endpoint: eventtypes.L3Endpoint{
							Addr:    "0.0.0.0",
							Version: 4,
							Kind:    eventtypes.EndpointKindRaw,
						},
						Port: 9090,
					},
					DstEndpoint: eventtypes.L4Endpoint{
						L3Endpoint: eventtypes.L3Endpoint{
							Addr:    "0.0.0.0",
							Version: 4,
							Kind:    eventtypes.EndpointKindRaw,
						},
						Port: 0,
					},
					Status: "LISTEN",
				}
				expectedEntry.K8s.Node = nodeName

				// Socket gadget doesn't provide container data yet. See issue #744.
				expectedEntry.K8s.ContainerName = ""

				normalize := func(e *snapshotsocketTypes.Event) {
					e.InodeNumber = 0
					e.NetNsID = 0

					e.K8s.ContainerName = ""
					// TODO: Verify container runtime and container name
					e.Runtime.RuntimeName = ""
					e.Runtime.ContainerName = ""
					e.Runtime.ContainerID = ""
					e.Runtime.ContainerImageDigest = ""
					e.Runtime.ContainerStartedAt = 0
				}

				match.MatchEntries(t, match.JSONSingleArrayMode, output, normalize, expectedEntry)
			},
		},
	}
	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}

func TestSnapshotUDPSocket(t *testing.T) {
	if DefaultTestComponent != InspektorGadgetTestComponent {
		t.Skip("Skip running test with test component different than kubectl-gadget")
	}

	if *k8sDistro == K8sDistroARO {
		t.Skip("Skip running snapshot socket gadget on ARO: iterators are not supported on kernel 4.18.0-305.19.1.el8_4.x86_64")
	}

	ns := GenerateTestNamespaceName("test-udp-socket-collector")

	t.Parallel()

	commandsPreTest := []TestStep{
		CreateTestNamespaceCommand(ns),
		BusyboxPodCommand(ns, "nc -u -l -p 9091"),
		WaitUntilTestPodReadyCommand(ns),
	}
	RunTestSteps(commandsPreTest, t, WithCbBeforeCleanup(PrintLogsFn(ns)))

	t.Cleanup(func() {
		commandsPostTest := []TestStep{
			DeleteTestNamespaceCommand(ns),
		}
		RunTestSteps(commandsPostTest, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	nodeName := GetPodNode(t, ns, "test-pod")

	t.Log("Node name:", nodeName)

	commands := []TestStep{
		&Command{
			Name: "RunSnapshotUDPSocketGadget",
			Cmd:  fmt.Sprintf("$KUBECTL_GADGET snapshot socket -n %s -o json --node %s", ns, nodeName),
			ValidateOutput: func(t *testing.T, output string) {
				t.Log("Output:", output)

				expectedEntry := &snapshotsocketTypes.Event{
					Event:    BuildBaseEventK8s(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)),
					Protocol: "UDP",
					SrcEndpoint: eventtypes.L4Endpoint{
						L3Endpoint: eventtypes.L3Endpoint{
							Addr:    "0.0.0.0",
							Version: 4,
							Kind:    eventtypes.EndpointKindRaw,
						},
						Port: 9091,
					},
					DstEndpoint: eventtypes.L4Endpoint{
						L3Endpoint: eventtypes.L3Endpoint{
							Addr:    "0.0.0.0",
							Version: 4,
							Kind:    eventtypes.EndpointKindRaw,
						},
						Port: 0,
					},
					Status: "LISTEN",
				}
				expectedEntry.K8s.Node = nodeName

				// Socket gadget doesn't provide container data yet. See issue #744.
				expectedEntry.K8s.ContainerName = ""

				normalize := func(e *snapshotsocketTypes.Event) {
					e.InodeNumber = 0
					e.NetNsID = 0

					e.K8s.ContainerName = ""
					// TODO: Verify container runtime and container name
					e.Runtime.RuntimeName = ""
					e.Runtime.ContainerName = ""
					e.Runtime.ContainerID = ""
					e.Runtime.ContainerImageDigest = ""
					e.Runtime.ContainerStartedAt = 0
				}

				match.MatchEntries(t, match.JSONSingleArrayMode, output, normalize, expectedEntry)
			},
		},
	}
	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
