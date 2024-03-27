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
	"strings"
	"testing"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	tracenetworkTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestTraceNetwork(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-network")

	commandsPreTest := []*Command{
		CreateTestNamespaceCommand(ns),
		PodCommand("nginx-pod", "nginx", ns, "", ""),
		WaitUntilPodReadyCommand(ns, "nginx-pod"),
	}

	RunTestSteps(commandsPreTest, t)
	nginxIP := GetTestPodIP(t, ns, "nginx-pod")
	nginxIPVersion := GetIPVersion(t, nginxIP)

	commonDataOpts := []CommonDataOption{WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)}

	var extraArgs string
	switch DefaultTestComponent {
	case IgTestComponent:
		extraArgs = "--runtimes=" + containerRuntime
		commonDataOpts = append(commonDataOpts, WithRuntimeMetadata(containerRuntime))
	case InspektorGadgetTestComponent:
		extraArgs = "-n " + ns
	}

	traceNetworkCmd := &Command{
		Name:         "StartTraceNetworkGadget",
		Cmd:          fmt.Sprintf("%s trace network -o json %s", DefaultTestComponent, extraArgs),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			testPodIP := GetTestPodIP(t, ns, "test-pod")
			testPodIPVersion := GetIPVersion(t, testPodIP)

			expectedEntries := []*tracenetworkTypes.Event{
				{
					Event:   BuildBaseEvent(ns, commonDataOpts...),
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
								},
							},
							Runtime: eventtypes.BasicRuntimeMetadata{
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

			if DefaultTestComponent == IgTestComponent {
				expectedEntries[1].Event.Runtime.ContainerName = "nginx-pod"
				expectedEntries[1].Event.Runtime.RuntimeName = eventtypes.String2RuntimeName(containerRuntime)
			}

			if DefaultTestComponent == InspektorGadgetTestComponent {
				expectedEntries[0].PodIP = testPodIP
				expectedEntries[0].PodLabels = map[string]string{"run": "test-pod"}
				expectedEntries[0].DstEndpoint.Namespace = ns
				expectedEntries[0].DstEndpoint.Name = "nginx-pod"
				expectedEntries[0].DstEndpoint.Kind = eventtypes.EndpointKindPod
				expectedEntries[0].DstEndpoint.PodLabels = map[string]string{"run": "nginx-pod"}

				expectedEntries[1].PodIP = nginxIP
				expectedEntries[1].PodLabels = map[string]string{"run": "nginx-pod"}
				expectedEntries[1].DstEndpoint.Namespace = ns
				expectedEntries[1].DstEndpoint.Name = "test-pod"
				expectedEntries[1].DstEndpoint.Kind = eventtypes.EndpointKindPod
				expectedEntries[1].DstEndpoint.PodLabels = map[string]string{"run": "test-pod"}
			}

			// TODO: Handle it once we support getting container image name from docker
			if isDockerRuntime {
				expectedEntries[1].CommonData.Runtime.ContainerImageName = ""
			}

			normalize := func(e *tracenetworkTypes.Event) {
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

				if DefaultTestComponent == IgTestComponent {
					if containerRuntime == ContainerRuntimeDocker || containerRuntime == ContainerRuntimeCRIO {
						cn := e.K8s.ContainerName
						if strings.HasPrefix(e.Runtime.ContainerName, fmt.Sprintf("k8s_%s_%s_%s_", cn, cn, ns)) {
							e.Runtime.ContainerName = cn
						}
					}
					if isDockerRuntime {
						e.Runtime.ContainerImageName = ""
					}
				} else if DefaultTestComponent == InspektorGadgetTestComponent {
					e.PodHostIP = ""
					e.K8s.Node = ""
					e.Runtime.RuntimeName = ""
					e.Runtime.ContainerName = ""
				}
			}

			ExpectEntriesToMatch(t, output, normalize, expectedEntries...)
		},
	}

	commands := []*Command{
		traceNetworkCmd,
		BusyboxPodRepeatCommand(ns, fmt.Sprintf("wget -q -O /dev/null %s:80", nginxIP)),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
