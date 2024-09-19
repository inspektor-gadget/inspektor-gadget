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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

// Only CRI-O enriches the container with the pod labels by default.
func addPodLabels(podName string) map[string]string {
	if containerRuntime == ContainerRuntimeCRIO {
		return map[string]string{"run": podName}
	}
	return nil
}

func newListContainerTestStep(
	cmd string,
	cn, pod, podUID, ns, runtime, runtimeContainerName string,
	verifyOutput func(*testing.T, string, func(*containercollection.Container), *containercollection.Container),
) *Command {
	return &Command{
		Name: "RunListContainers",
		Cmd:  cmd,
		ValidateOutput: func(t *testing.T, output string) {
			expectedContainer := &containercollection.Container{
				K8s: containercollection.K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						ContainerName: cn,
						PodName:       pod,
						Namespace:     ns,
						PodLabels:     addPodLabels(pod),
					},
					PodUID: podUID,
				},
				Runtime: containercollection.RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						RuntimeName:        types.String2RuntimeName(runtime),
						ContainerName:      runtimeContainerName,
						ContainerImageName: "docker.io/library/busybox:latest",
					},
				},
			}

			// Docker can provide different values for ContainerImageName. See `getContainerImageNamefromImage`
			if isDockerRuntime {
				expectedContainer.Runtime.ContainerImageName = ""
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

				c.SandboxId = ""
				c.K8s.PodLabels = addPodLabels(pod)
				c.Runtime.ContainerID = ""
				c.Runtime.ContainerPID = 0
				c.Runtime.ContainerImageDigest = ""
				c.Runtime.ContainerStartedAt = 0

				// Docker can provide different values for ContainerImageName. See `getContainerImageNamefromImage`
				if isDockerRuntime {
					c.Runtime.ContainerImageName = ""
				}
			}

			verifyOutput(t, output, normalize, expectedContainer)
		},
	}
}

func TestListContainers(t *testing.T) {
	if DefaultTestComponent != IgTestComponent {
		t.Skip("Skip running list-containers with test component different than ig")
	}

	t.Parallel()

	cn := "test-list-containers"
	pod := cn
	ns := GenerateTestNamespaceName(pod)

	t.Cleanup(func() {
		commandsPostTest := []TestStep{
			DeleteTestNamespaceCommand(ns),
		}
		RunTestSteps(commandsPostTest, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	commands := []TestStep{
		CreateTestNamespaceCommand(ns),
		PodCommand(cn, "busybox", ns, `["sleep", "inf"]`, ""),
		WaitUntilPodReadyCommand(ns, pod),
	}
	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))

	podUID := GetPodUID(t, ns, pod)

	// Containerd name the container with the Kubernetes container name, while
	// Docker and CRI-O use a composed name.
	runtimeContainerName := cn
	if containerRuntime == ContainerRuntimeDocker || containerRuntime == ContainerRuntimeCRIO {
		// Test container shouldn't have been restarted, so append "0".
		runtimeContainerName = "k8s_" + cn + "_" + pod + "_" + ns + "_" + podUID + "_" + "0"
	}

	t.Run("ListAll", func(t *testing.T) {
		t.Parallel()

		listContainerTestStep := newListContainerTestStep(
			fmt.Sprintf("ig list-containers -o json --runtimes=%s", containerRuntime),
			cn, pod, podUID, ns, containerRuntime, runtimeContainerName,
			func(t *testing.T, o string, f func(*containercollection.Container), c *containercollection.Container) {
				match.MatchEntries(t, match.JSONSingleArrayMode, o, f, c)
			},
		)
		RunTestSteps([]TestStep{listContainerTestStep}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("FilteredList", func(t *testing.T) {
		t.Parallel()

		listContainerTestStep := newListContainerTestStep(
			fmt.Sprintf("ig list-containers -o json --runtimes=%s --containername=%s", containerRuntime, runtimeContainerName),
			cn, pod, podUID, ns, containerRuntime, runtimeContainerName,
			func(t *testing.T, output string, f func(*containercollection.Container), c *containercollection.Container) {
				match.MatchAllEntries(t, match.JSONSingleArrayMode, output, f, c)
			},
		)
		RunTestSteps([]TestStep{listContainerTestStep}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})
}

func TestWatchCreatedContainers(t *testing.T) {
	if DefaultTestComponent != IgTestComponent {
		t.Skip("Skip running list-containers --watch for created containers with test component different than ig")
	}

	t.Parallel()

	cn := "test-created-containers"
	pod := cn
	ns := GenerateTestNamespaceName(pod)

	watchContainersCmd := &Command{
		Name: "RunWatchContainers",
		// TODO: Filter by namespace once we support it.
		Cmd:          fmt.Sprintf("ig list-containers -o json --runtimes=%s --watch", containerRuntime),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedEvent := &containercollection.PubSubEvent{
				Type: containercollection.EventTypeAddContainer,
				Container: &containercollection.Container{
					K8s: containercollection.K8sMetadata{
						BasicK8sMetadata: types.BasicK8sMetadata{
							ContainerName: cn,
							PodName:       pod,
							Namespace:     ns,
							PodLabels:     addPodLabels(pod),
						},
					},
					Runtime: containercollection.RuntimeMetadata{
						BasicRuntimeMetadata: types.BasicRuntimeMetadata{
							RuntimeName:        types.String2RuntimeName(containerRuntime),
							ContainerName:      cn,
							ContainerImageName: "docker.io/library/busybox:latest",
						},
					},
				},
			}

			// Docker can provide different values for ContainerImageName. See `getContainerImageNamefromImage`
			if isDockerRuntime {
				expectedEvent.Container.Runtime.ContainerImageName = ""
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

				e.Container.SandboxId = ""
				e.Container.K8s.PodLabels = addPodLabels(pod)
				e.Container.K8s.PodUID = ""
				e.Container.Runtime.ContainerID = ""
				e.Container.Runtime.ContainerPID = 0
				e.Container.Runtime.ContainerImageDigest = ""
				e.Container.Runtime.ContainerStartedAt = 0

				// Docker and CRI-O use a custom container name composed, among
				// other things, by the pod UID. We don't know the pod UID in
				// advance, so we can't match the expected container name.
				// TODO: Create a test for this once we support filtering by k8s
				// container name. See
				// https://github.com/inspektor-gadget/inspektor-gadget/issues/1403.
				if e.Container.Runtime.RuntimeName == ContainerRuntimeDocker ||
					e.Container.Runtime.RuntimeName == ContainerRuntimeCRIO {
					e.Container.Runtime.ContainerName = cn
				}

				// Docker can provide different values for ContainerImageName. See `getContainerImageNamefromImage`
				if e.Container.Runtime.RuntimeName == ContainerRuntimeDocker {
					e.Container.Runtime.ContainerImageName = ""
				}
			}

			// Watching containers is a command that needs to be started before
			// the container is created, so we can't filter by container name
			// neither use MatchAllEntries here.
			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEvent)
		},
	}

	commands := []TestStep{
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
	if DefaultTestComponent != IgTestComponent {
		t.Skip("Skip running list-containers --watch for deleted containers with test component different than ig")
	}

	t.Parallel()

	cn := "test-deleted-container"
	pod := cn
	ns := GenerateTestNamespaceName(pod)

	watchContainersCmd := &Command{
		Name:         "RunWatchContainers",
		Cmd:          fmt.Sprintf("ig list-containers -o json --runtimes=%s --watch", containerRuntime),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedEvent := &containercollection.PubSubEvent{
				Type: containercollection.EventTypeRemoveContainer,
				Container: &containercollection.Container{
					K8s: containercollection.K8sMetadata{
						BasicK8sMetadata: types.BasicK8sMetadata{
							ContainerName: cn,
							PodName:       pod,
							Namespace:     ns,
							PodLabels:     addPodLabels(pod),
						},
					},
					Runtime: containercollection.RuntimeMetadata{
						BasicRuntimeMetadata: types.BasicRuntimeMetadata{
							RuntimeName:        types.String2RuntimeName(containerRuntime),
							ContainerName:      cn,
							ContainerImageName: "docker.io/library/busybox:latest",
						},
					},
				},
			}

			// Docker can provide different values for ContainerImageName. See `getContainerImageNamefromImage`
			if isDockerRuntime {
				expectedEvent.Container.Runtime.ContainerImageName = ""
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

				e.Container.SandboxId = ""
				e.Container.K8s.PodLabels = addPodLabels(pod)
				e.Container.K8s.PodUID = ""
				e.Container.Runtime.ContainerID = ""
				e.Container.Runtime.ContainerPID = 0
				e.Container.Runtime.ContainerImageDigest = ""
				e.Container.Runtime.ContainerStartedAt = 0

				// Docker and CRI-O use a custom container name composed, among
				// other things, by the pod UID. We don't know the pod UID in
				// advance, so we can't match the expected container name.
				// TODO: Create a test for this once we support filtering by k8s
				// container name. See
				// https://github.com/inspektor-gadget/inspektor-gadget/issues/1403.
				if e.Container.Runtime.RuntimeName == ContainerRuntimeDocker ||
					e.Container.Runtime.RuntimeName == ContainerRuntimeCRIO {
					e.Container.Runtime.ContainerName = cn
				}

				// Docker can provide different values for ContainerImageName. See `getContainerImageNamefromImage`
				if e.Container.Runtime.RuntimeName == ContainerRuntimeDocker {
					e.Container.Runtime.ContainerImageName = ""
				}
			}

			// Watching containers is a command that needs to be started before
			// the container is created, so we can't filter by container name
			// neither use MatchAllEntries here.
			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEvent)
		},
	}

	commands := []TestStep{
		CreateTestNamespaceCommand(ns),
		PodCommand(pod, "busybox", ns, `["sleep", "inf"]`, ""),
		WaitUntilPodReadyCommand(ns, pod),
		watchContainersCmd,
		&Command{
			Name: "DeletePod",
			Cmd:  fmt.Sprintf("kubectl delete pod %s -n %s", pod, ns),
		},
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}

func TestPodWithSecurityContext(t *testing.T) {
	if DefaultTestComponent != IgTestComponent {
		t.Skip("Skip running list-containers --watch for pod security context with test component different than ig")
	}

	t.Parallel()
	cn := "test-security-context"
	po := cn
	ns := GenerateTestNamespaceName(cn)

	watchContainersCmd := &Command{
		Name:         "RunWatchContainers",
		Cmd:          fmt.Sprintf("ig list-containers -o json --runtimes=%s --watch", containerRuntime),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedEvent := &containercollection.PubSubEvent{
				Type: containercollection.EventTypeAddContainer,
				Container: &containercollection.Container{
					K8s: containercollection.K8sMetadata{
						BasicK8sMetadata: types.BasicK8sMetadata{
							ContainerName: cn,
							PodName:       po,
							Namespace:     ns,
							PodLabels:     addPodLabels(po),
						},
					},
					Runtime: containercollection.RuntimeMetadata{
						BasicRuntimeMetadata: types.BasicRuntimeMetadata{
							RuntimeName:        types.String2RuntimeName(containerRuntime),
							ContainerName:      cn,
							ContainerImageName: "docker.io/library/busybox:latest",
						},
					},
				},
			}

			// Docker can provide different values for ContainerImageName. See `getContainerImageNamefromImage`
			if isDockerRuntime {
				expectedEvent.Container.Runtime.ContainerImageName = ""
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

				e.Container.SandboxId = ""
				e.Container.Runtime.ContainerID = ""
				e.Container.Runtime.ContainerPID = 0
				e.Container.Runtime.ContainerImageDigest = ""
				e.Container.Runtime.ContainerStartedAt = 0
				e.Container.K8s.PodLabels = addPodLabels(po)
				e.Container.K8s.PodUID = ""

				// Docker and CRI-O use a custom container name composed, among
				// other things, by the pod UID. We don't know the pod UID in
				// advance, so we can't match the expected container name.
				// TODO: Create a test for this once we support filtering by k8s
				// container name. See
				// https://github.com/inspektor-gadget/inspektor-gadget/issues/1403.
				if e.Container.Runtime.RuntimeName == ContainerRuntimeDocker ||
					e.Container.Runtime.RuntimeName == ContainerRuntimeCRIO {
					e.Container.Runtime.ContainerName = cn
				}

				// Docker can provide different values for ContainerImageName. See `getContainerImageNamefromImage`
				if e.Container.Runtime.RuntimeName == ContainerRuntimeDocker {
					e.Container.Runtime.ContainerImageName = ""
				}
			}

			// Watching containers is a command that needs to be started before
			// the container is created, so we can't filter by container name
			// neither use MatchAllEntries here.
			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEvent)
		},
	}

	securityContextPodYaml := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
  labels:
    run: %s
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 1001
    fsGroup: 1002
  restartPolicy: Never
  terminationGracePeriodSeconds: 0
  containers:
  - name: %s
    image: busybox
    command: ["sleep", "inf"]
`, po, ns, po, cn)

	commands := []TestStep{
		CreateTestNamespaceCommand(ns),
		watchContainersCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		&Command{
			Name:           "RunTestPodWithSecurityContext",
			Cmd:            fmt.Sprintf("echo '%s' | kubectl apply -f -", securityContextPodYaml),
			ExpectedRegexp: fmt.Sprintf("pod/%s created", po),
		},
		WaitUntilPodReadyCommand(ns, po),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
