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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func newListContainerTestStep(
	cmd string,
	cn, pod, podUID, ns, runtime, runtimeContainerName string,
	verifyOutput func(string, func(*containercollection.Container), *containercollection.Container) error,
) *Command {
	return &Command{
		Name: "RunListContainers",
		Cmd:  cmd,
		ExpectedOutputFn: func(output string) error {
			expectedContainer := &containercollection.Container{
				K8s: containercollection.K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Container: cn,
						Pod:       pod,
						Namespace: ns,
					},
					PodUID: podUID,
				},
				Runtime: containercollection.RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						Runtime:   types.String2RuntimeName(runtime),
						Container: runtimeContainerName,
					},
				},
			}

			normalize := func(c *containercollection.Container) {
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
				c.Runtime.ContainerID = ""
			}

			return verifyOutput(output, normalize, expectedContainer)
		},
	}
}

func TestListContainers(t *testing.T) {
	t.Parallel()

	cn := "test-list-containers"
	pod := cn
	ns := GenerateTestNamespaceName(pod)

	t.Cleanup(func() {
		commandsPostTest := []*Command{
			DeleteTestNamespaceCommand(ns),
		}
		RunTestSteps(commandsPostTest, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		PodCommand(cn, "busybox", ns, `["sleep", "inf"]`, ""),
		WaitUntilPodReadyCommand(ns, pod),
	}
	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))

	podUID, err := GetPodUID(ns, pod)
	if err != nil {
		t.Fatalf("getting pod UID: %s", err)
	}

	// Containerd name the container with the Kubernetes container name, while
	// Docker uses a composed name.
	runtimeContainerName := cn
	if *containerRuntime == ContainerRuntimeDocker || *containerRuntime == ContainerRuntimeCRIO {
		// Test container shouldn't have been restarted, so append "0".
		runtimeContainerName = "k8s_" + cn + "_" + pod + "_" + ns + "_" + podUID + "_" + "0"
	}

	t.Run("ListAll", func(t *testing.T) {
		t.Parallel()

		listContainerTestStep := newListContainerTestStep(
			fmt.Sprintf("ig list-containers -o json --runtimes=%s", *containerRuntime),
			cn, pod, podUID, ns, *containerRuntime, runtimeContainerName,
			func(o string, f func(*containercollection.Container), c *containercollection.Container) error {
				return ExpectEntriesInArrayToMatch(o, f, c)
			},
		)
		RunTestSteps([]*Command{listContainerTestStep}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("FilteredList", func(t *testing.T) {
		t.Parallel()

		listContainerTestStep := newListContainerTestStep(
			fmt.Sprintf("ig list-containers -o json --runtimes=%s --containername=%s", *containerRuntime, runtimeContainerName),
			cn, pod, podUID, ns, *containerRuntime, runtimeContainerName,
			func(o string, f func(*containercollection.Container), c *containercollection.Container) error {
				return ExpectAllInArrayToMatch(o, f, c)
			},
		)
		RunTestSteps([]*Command{listContainerTestStep}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})
}

func TestWatchCreatedContainers(t *testing.T) {
	t.Parallel()

	cn := "test-created-containers"
	pod := cn
	ns := GenerateTestNamespaceName(pod)

	watchContainersCmd := &Command{
		Name: "RunWatchContainers",
		// TODO: Filter by namespace once we support it.
		Cmd:          fmt.Sprintf("ig list-containers -o json --runtimes=%s --watch", *containerRuntime),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEvent := &containercollection.PubSubEvent{
				Type: containercollection.EventTypeAddContainer,
				Container: &containercollection.Container{
					K8s: containercollection.K8sMetadata{
						BasicK8sMetadata: types.BasicK8sMetadata{
							Container: cn,
							Pod:       pod,
							Namespace: ns,
						},
					},
					Runtime: containercollection.RuntimeMetadata{
						BasicRuntimeMetadata: types.BasicRuntimeMetadata{
							Runtime:   types.String2RuntimeName(*containerRuntime),
							Container: cn,
						},
					},
				},
			}

			normalize := func(e *containercollection.PubSubEvent) {
				e.Container.Pid = 0
				e.Container.OciConfig = nil
				e.Container.Bundle = ""
				e.Container.Mntns = 0
				e.Container.Netns = 0
				e.Container.CgroupPath = ""
				e.Container.CgroupID = 0
				e.Container.CgroupV1 = ""
				e.Container.CgroupV2 = ""
				e.Timestamp = ""

				e.Container.K8s.Labels = nil
				e.Container.K8s.PodUID = ""
				e.Container.Runtime.ContainerID = ""

				// Docker and CRI-O uses a custom container name composed, among
				// other things, by the pod UID. We don't know the pod UID in
				// advance, so we can't match the expected container name.
				// TODO: Create a test for this once we support filtering by k8s
				// container name. See
				// https://github.com/inspektor-gadget/inspektor-gadget/issues/1403.
				if e.Container.Runtime.Runtime == ContainerRuntimeDocker ||
					e.Container.Runtime.Runtime == ContainerRuntimeCRIO {
					e.Container.Runtime.Container = cn
				}
			}

			return ExpectEntriesToMatch(output, normalize, expectedEvent)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		watchContainersCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		PodCommand(pod, "busybox", ns, `["sleep", "inf"]`, ""),
		WaitUntilPodReadyCommand(ns, pod),
		DeleteTestNamespaceCommand(ns),
	}
	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}

func TestWatchDeletedContainers(t *testing.T) {
	t.Parallel()

	cn := "test-deleted-container"
	pod := cn
	ns := GenerateTestNamespaceName(pod)

	watchContainersCmd := &Command{
		Name:         "RunWatchContainers",
		Cmd:          fmt.Sprintf("ig list-containers -o json --runtimes=%s --watch", *containerRuntime),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEvent := &containercollection.PubSubEvent{
				Type: containercollection.EventTypeRemoveContainer,
				Container: &containercollection.Container{
					K8s: containercollection.K8sMetadata{
						BasicK8sMetadata: types.BasicK8sMetadata{
							Container: cn,
							Pod:       pod,
							Namespace: ns,
						},
					},
					Runtime: containercollection.RuntimeMetadata{
						BasicRuntimeMetadata: types.BasicRuntimeMetadata{
							Runtime:   types.String2RuntimeName(*containerRuntime),
							Container: cn,
						},
					},
				},
			}

			normalize := func(e *containercollection.PubSubEvent) {
				e.Container.Runtime.ContainerID = ""
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

				// Docker and CRI-O uses a custom container name composed, among
				// other things, by the pod UID. We don't know the pod UID in
				// advance, so we can't match the expected container name.
				// TODO: Create a test for this once we support filtering by k8s
				// container name. See
				// https://github.com/inspektor-gadget/inspektor-gadget/issues/1403.
				if e.Container.Runtime.Runtime == ContainerRuntimeDocker ||
					e.Container.Runtime.Runtime == ContainerRuntimeCRIO {
					e.Container.Runtime.Container = cn
				}
			}

			return ExpectEntriesToMatch(output, normalize, expectedEvent)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		PodCommand(pod, "busybox", ns, `["sleep", "inf"]`, ""),
		WaitUntilPodReadyCommand(ns, pod),
		watchContainersCmd,
		{
			Name: "DeletePod",
			Cmd:  fmt.Sprintf("kubectl delete pod %s -n %s", pod, ns),
		},
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
