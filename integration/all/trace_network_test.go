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

// import (
// 	"fmt"
// 	"testing"

// 	. "github.com/inspektor-gadget/inspektor-gadget/integration"
// 	tracenetworkTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
// 	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
// )

// func TestTraceNetwork(t *testing.T) {
// 	t.Parallel()
// 	ns := GenerateTestNamespaceName("test-trace-network")

// 	commandsPreTest := []*Command{
// 		CreateTestNamespaceCommand(ns),
// 		PodCommand("nginx-pod", "nginx", ns, "", ""),
// 		WaitUntilPodReadyCommand(ns, "nginx-pod"),
// 	}

// 	RunTestSteps(commandsPreTest, t)
// 	nginxIP := GetTestPodIP(t, ns, "nginx-pod")
// 	nginxIPVersion := GetIPVersion(t, nginxIP)

// 	commonDataOpts := []CommonDataOption{WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)}

// 	var extraArgs string
// 	switch DefaultTestComponent {
// 	case IgTestComponent:
// 		extraArgs = "--runtimes=" + containerRuntime
// 		commonDataOpts = append(commonDataOpts, WithRuntimeMetadata(containerRuntime))
// 	case InspektorGadgetTestComponent:
// 		extraArgs = "-n " + ns
// 	}

// 	traceNetworkCmd := &Command{
// 		Name:         "StartTraceNetworkGadget",
// 		Cmd:          fmt.Sprintf("%s trace network -o json %s", DefaultTestComponent, extraArgs),
// 		StartAndStop: true,
// 		ValidateOutput: func(t *testing.T, output string) {
// 			testPodIP := GetTestPodIP(t, ns, "test-pod")
// 			testPodIPVersion := GetIPVersion(t, testPodIP)

// 			expectedEntries := []*tracenetworkTypes.Event{
// 				{
// 					Event:     BuildBaseEvent(ns, commonDataOpts...),
// 					Comm:      "wget",
// 					Uid:       0,
// 					Gid:       0,
// 					PktType:   "OUTGOING",
// 					Proto:     "TCP",
// 					Port:      80,
// 					PodIP:     testPodIP,
// 					PodLabels: map[string]string{"run": "test-pod"},
// 					DstEndpoint: eventtypes.L3Endpoint{
// 						Addr:      nginxIP,
// 						Version:   nginxIPVersion,
// 						Namespace: ns,
// 						Name:      "nginx-pod",
// 						Kind:      eventtypes.EndpointKindPod,
// 						PodLabels: map[string]string{"run": "nginx-pod"},
// 					},
// 				},
// 				{
// 					Event: eventtypes.Event{
// 						Type: eventtypes.NORMAL,
// 						CommonData: eventtypes.CommonData{
// 							K8s: eventtypes.K8sMetadata{
// 								BasicK8sMetadata: eventtypes.BasicK8sMetadata{
// 									Namespace:     ns,
// 									PodName:       "nginx-pod",
// 									ContainerName: "nginx-pod",
// 								},
// 							},
// 							Runtime: eventtypes.BasicRuntimeMetadata{
// 								ContainerImageName: "docker.io/library/nginx:latest",
// 							},
// 						},
// 					},
// 					Comm:      "nginx",
// 					PktType:   "HOST",
// 					Proto:     "TCP",
// 					PodIP:     nginxIP,
// 					PodLabels: map[string]string{"run": "nginx-pod"},
// 					Port:      80,
// 					DstEndpoint: eventtypes.L3Endpoint{
// 						Addr:      testPodIP,
// 						Version:   testPodIPVersion,
// 						Namespace: ns,
// 						Name:      "test-pod",
// 						Kind:      eventtypes.EndpointKindPod,
// 						PodLabels: map[string]string{"run": "test-pod"},
// 					},
// 				},
// 			}

// 			// TODO: Handle it once we support getting container image name from docker
// 			if isDockerRuntime {
// 				expectedEntries[1].CommonData.Runtime.ContainerImageName = ""
// 			}

// 			normalize := func(e *tracenetworkTypes.Event) {
// 				e.Timestamp = 0
// 				e.PodHostIP = ""
// 				e.MountNsID = 0
// 				e.NetNsID = 0
// 				e.Pid = 0
// 				e.Tid = 0
// 				// nginx uses multiple processes, in this case Inspektor Gadget is
// 				// not able to determine the UID / GID in a reliable way.
// 				e.Uid = 0
// 				e.Gid = 0

// 				e.K8s.Node = ""
// 				e.Runtime.RuntimeName = ""
// 				e.Runtime.ContainerName = ""
// 				e.Runtime.ContainerID = ""
// 				e.Runtime.ContainerImageDigest = ""
// 			}

// 			ExpectEntriesToMatch(t, output, normalize, expectedEntries...)
// 		},
// 	}

// 	commands := []*Command{
// 		traceNetworkCmd,
// 		BusyboxPodRepeatCommand(ns, fmt.Sprintf("wget -q -O /dev/null %s:80", nginxIP)),
// 		WaitUntilTestPodReadyCommand(ns),
// 		DeleteTestNamespaceCommand(ns),
// 	}

// 	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
// }
