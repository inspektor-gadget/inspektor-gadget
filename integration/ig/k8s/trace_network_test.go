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

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	networkTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestTraceNetwork(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-network")

	commandsPreTest := []TestStep{
		CreateTestNamespaceCommand(ns),
		PodCommand("nginx-pod", "nginx", ns, "", ""),
		WaitUntilPodReadyCommand(ns, "nginx-pod"),
	}

	RunTestSteps(commandsPreTest, t)
	nginxIP := GetTestPodIP(t, ns, "nginx-pod")
	nginxIPVersion := GetIPVersion(t, nginxIP)

	traceNetworkCmd := &Command{
		Name:         "TraceNetwork",
		Cmd:          fmt.Sprintf("ig trace network -o json --runtimes=%s", *containerRuntime),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			testPodIP := GetTestPodIP(t, ns, "test-pod")
			testPodIPVersion := GetIPVersion(t, testPodIP)
			isDockerRuntime := *containerRuntime == ContainerRuntimeDocker
			isCrioRuntime := *containerRuntime == ContainerRuntimeCRIO

			addPodLabels := func() map[string]string {
				if isCrioRuntime {
					return map[string]string{"run": "nginx-pod"}
				}
				return nil
			}

			expectedEntries := []*networkTypes.Event{
				{
					Event: BuildBaseEvent(ns,
						WithRuntimeMetadata(*containerRuntime),
						WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime),
						WithPodLabels("test-pod", ns, isCrioRuntime),
					),
					Comm:    "wget",
					Uid:     0,
					Gid:     0,
					PktType: "OUTGOING",
					Proto:   "TCP",
					Port:    80,
					DstEndpoint: eventtypes.L3Endpoint{
						Addr:    nginxIP,
						Version: nginxIPVersion,
					},
				},
				{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
						CommonData: eventtypes.CommonData{
							K8s: eventtypes.K8sMetadata{
								BasicK8sMetadata: eventtypes.BasicK8sMetadata{
									Namespace:     ns,
									PodName:       "nginx-pod",
									ContainerName: "nginx-pod",
									PodLabels:     addPodLabels(),
								},
							},
							Runtime: eventtypes.BasicRuntimeMetadata{
								ContainerName:      "nginx-pod",
								RuntimeName:        eventtypes.String2RuntimeName(*containerRuntime),
								ContainerImageName: "docker.io/library/nginx:latest",
							},
						},
					},
					Comm:    "nginx",
					PktType: "HOST",
					Proto:   "TCP",
					Port:    80,
					DstEndpoint: eventtypes.L3Endpoint{
						Addr:    testPodIP,
						Version: testPodIPVersion,
					},
				},
			}

			// TODO: Handle once we can get ContainerImageName from docker
			if isDockerRuntime {
				expectedEntries[1].Event.Runtime.ContainerImageName = ""
			}

			normalize := func(e *networkTypes.Event) {
				// Docker and CRI-O use a custom container name composed, among
				// other things, by the pod UID. We don't know the pod UID in
				// advance, so we can't match the exact expected container name.
				if *containerRuntime == ContainerRuntimeDocker || *containerRuntime == ContainerRuntimeCRIO {
					cn := e.K8s.ContainerName
					if strings.HasPrefix(e.Runtime.ContainerName, fmt.Sprintf("k8s_%s_%s_%s_", cn, cn, ns)) {
						e.Runtime.ContainerName = cn
					}
				}

				e.Timestamp = 0
				e.MountNsID = 0
				e.NetNsID = 0
				e.Pid = 0
				e.Tid = 0
				// nginx uses multiple processes, in this case Inspektor Gadget is
				// not able to determine the UID / GID in a reliable way.
				e.Uid = 0
				e.Gid = 0

				e.Runtime.ContainerID = ""
				e.Runtime.ContainerImageDigest = ""

				// Docker can provide different values for ContainerImageName. See `getContainerImageNamefromImage`
				if isDockerRuntime {
					e.Runtime.ContainerImageName = ""
				}
			}

			ExpectEntriesToMatch(t, output, normalize, expectedEntries...)
		},
	}

	commands := []TestStep{
		traceNetworkCmd,
		BusyboxPodRepeatCommand(ns, fmt.Sprintf("wget -q -O /dev/null %s:80", nginxIP)),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
