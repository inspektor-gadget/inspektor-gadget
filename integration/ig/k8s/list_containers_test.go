// Copyright 2022 The Inspektor Gadget authors
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
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
)

func TestListContainers(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-list-containers")

	listContainersCmd := &Command{
		Name: "RunListContainers",
		Cmd:  fmt.Sprintf("ig list-containers -o json --runtimes=%s", *containerRuntime),
		ExpectedOutputFn: func(output string) error {
			expectedContainer := &containercollection.Container{
				K8s: containercollection.K8sMetadata{
					Container: "test-pod",
					Pod:       "test-pod",
					Namespace: ns,
				},
				Runtime: containercollection.RuntimeMetadata{
					Runtime: *containerRuntime,
				},
			}

			normalize := func(c *containercollection.Container) {
				// TODO: Handle it once we support getting K8s container name for docker
				// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/737
				if *containerRuntime == ContainerRuntimeDocker {
					c.K8s.Container = "test-pod"
				}

				c.Runtime.ID = ""
				c.Pid = 0
				c.OciConfig = nil
				c.Bundle = ""
				c.Mntns = 0
				c.Netns = 0
				c.CgroupPath = ""
				c.CgroupID = 0
				c.CgroupV1 = ""
				c.CgroupV2 = ""
				c.K8s.Labels = nil
				c.K8s.PodUID = ""
			}

			return ExpectEntriesInArrayToMatch(output, normalize, expectedContainer)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		BusyboxPodCommand(ns, "sleep inf"),
		WaitUntilTestPodReadyCommand(ns),
		listContainersCmd,
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}

func TestFilterByContainerName(t *testing.T) {
	t.Parallel()
	cn := "test-filtered-container"
	ns := GenerateTestNamespaceName(cn)

	// TODO: Handle it once we support getting K8s container name for docker
	// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/737
	if *containerRuntime == ContainerRuntimeDocker {
		t.Skip("Skip TestFilterByContainerName on docker since we don't propagate the Kubernetes pod container name")
	}

	listContainersCmd := &Command{
		Name: "RunFilterByContainerName",
		Cmd:  fmt.Sprintf("ig list-containers -o json --runtimes=%s --containername=%s", *containerRuntime, cn),
		ExpectedOutputFn: func(output string) error {
			expectedContainer := &containercollection.Container{
				K8s: containercollection.K8sMetadata{
					Container: cn,
					Pod:       cn,
					Namespace: ns,
				},
				Runtime: containercollection.RuntimeMetadata{
					Runtime: *containerRuntime,
				},
			}

			normalize := func(c *containercollection.Container) {
				c.Runtime.ID = ""
				c.Pid = 0
				c.OciConfig = nil
				c.Bundle = ""
				c.Mntns = 0
				c.Netns = 0
				c.CgroupPath = ""
				c.CgroupID = 0
				c.CgroupV1 = ""
				c.CgroupV2 = ""
				c.K8s.Labels = nil
				c.K8s.PodUID = ""
			}

			return ExpectAllInArrayToMatch(output, normalize, expectedContainer)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		PodCommand(cn, "busybox", ns, `["sleep", "inf"]`, ""),
		WaitUntilPodReadyCommand(ns, cn),
		listContainersCmd,
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}

func TestWatchCreatedContainers(t *testing.T) {
	t.Parallel()
	cn := "test-created-container"
	ns := GenerateTestNamespaceName(cn)

	// TODO: Handle it once we support getting K8s container name for docker
	// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/737
	if *containerRuntime == ContainerRuntimeDocker {
		t.Skip("Skip TestWatchContainers on docker since we don't propagate the Kubernetes pod container name")
	}

	watchContainersCmd := &Command{
		Name:         "RunWatchContainers",
		Cmd:          fmt.Sprintf("ig list-containers -o json --runtimes=%s --containername=%s --watch", *containerRuntime, cn),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEvent := &containercollection.PubSubEvent{
				Type: containercollection.EventTypeAddContainer,
				Container: &containercollection.Container{
					K8s: containercollection.K8sMetadata{
						Container: cn,
						Pod:       cn,
						Namespace: ns,
					},
					Runtime: containercollection.RuntimeMetadata{
						Runtime: *containerRuntime,
					},
				},
			}

			normalize := func(e *containercollection.PubSubEvent) {
				e.Container.Runtime.ID = ""
				e.Container.Pid = 0
				e.Container.OciConfig = nil
				e.Container.Bundle = ""
				e.Container.Mntns = 0
				e.Container.Netns = 0
				e.Container.CgroupPath = ""
				e.Container.CgroupID = 0
				e.Container.CgroupV1 = ""
				e.Container.CgroupV2 = ""
				e.Container.K8s.Labels = nil
				e.Container.K8s.PodUID = ""
				e.Timestamp = ""
			}

			return ExpectAllToMatch(output, normalize, expectedEvent)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		watchContainersCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		PodCommand(cn, "busybox", ns, `["sleep", "inf"]`, ""),
		WaitUntilPodReadyCommand(ns, cn),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}

func TestWatchDeletedContainers(t *testing.T) {
	t.Parallel()
	cn := "test-deleted-container"
	ns := GenerateTestNamespaceName(cn)

	// TODO: Handle it once we support getting K8s container name for docker
	// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/737
	if *containerRuntime == ContainerRuntimeDocker {
		t.Skip("Skip TestWatchContainers on docker since we don't propagate the Kubernetes pod container name")
	}

	watchContainersCmd := &Command{
		Name:         "RunWatchContainers",
		Cmd:          fmt.Sprintf("ig list-containers -o json --runtimes=%s --containername=%s --watch", *containerRuntime, cn),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEvent := &containercollection.PubSubEvent{
				Type: containercollection.EventTypeRemoveContainer,
				Container: &containercollection.Container{
					K8s: containercollection.K8sMetadata{
						Container: cn,
						Pod:       cn,
						Namespace: ns,
					},
					Runtime: containercollection.RuntimeMetadata{
						Runtime: *containerRuntime,
					},
				},
			}

			normalize := func(e *containercollection.PubSubEvent) {
				e.Container.Runtime.ID = ""
				e.Container.Pid = 0
				e.Container.OciConfig = nil
				e.Container.Bundle = ""
				e.Container.Mntns = 0
				e.Container.Netns = 0
				e.Container.CgroupPath = ""
				e.Container.CgroupID = 0
				e.Container.CgroupV1 = ""
				e.Container.CgroupV2 = ""
				e.Container.K8s.Labels = nil
				e.Container.K8s.PodUID = ""
				e.Timestamp = ""
			}

			return ExpectEntriesToMatch(output, normalize, expectedEvent)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		PodCommand(cn, "busybox", ns, `["sleep", "inf"]`, ""),
		WaitUntilPodReadyCommand(ns, cn),
		watchContainersCmd,
		{
			Name: "DeletePod",
			Cmd:  fmt.Sprintf("kubectl delete pod %s -n %s", cn, ns),
		},
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
