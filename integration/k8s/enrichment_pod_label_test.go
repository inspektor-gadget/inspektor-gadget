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

func TestEnrichmentPodLabelExistingPod(t *testing.T) {
	if DefaultTestComponent != IgTestComponent {
		t.Skip("Skip running existing pod label enrichment test with test component different than ig")
	}

	t.Parallel()

	cn := "test-enrichment-pod-label-existing-pod"
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
		PodCommand(cn, "ghcr.io/inspektor-gadget/ci/busybox:latest", ns, `["sleep", "inf"]`, ""),
		WaitUntilPodReadyCommand(ns, pod),
	}
	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))

	podUID := GetPodUID(t, ns, pod)

	// Containerd and docker shim name the container with the Kubernetes container
	// name, while CRI-O and Docker use a composed name.
	runtimeContainerName := cn
	if containerRuntime == ContainerRuntimeCRIO || containerRuntime == ContainerRuntimeDocker {
		// Test container shouldn't have been restarted, so append "0".
		runtimeContainerName = "k8s_" + cn + "_" + pod + "_" + ns + "_" + podUID + "_" + "0"
	}

	listContainersCmd := &Command{
		Name: "RunListContainers",
		Cmd:  fmt.Sprintf("ig list-containers -o json --runtimes=%s --runtime-protocol=cri", containerRuntime),
		ValidateOutput: func(t *testing.T, output string) {
			expectedContainer := &containercollection.Container{
				K8s: containercollection.K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						ContainerName: cn,
						PodName:       pod,
						Namespace:     ns,
						PodLabels: map[string]string{
							"run": cn,
						},
					},
					PodUID: podUID,
				},
				Runtime: containercollection.RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						RuntimeName:        types.String2RuntimeName(containerRuntime),
						ContainerName:      runtimeContainerName,
						ContainerImageName: "ghcr.io/inspektor-gadget/ci/busybox:latest",
					},
				},
			}

			// Docker can provide different values for ContainerImageName. See `getContainerImageNamefromImage`
			if isDockerRuntime {
				expectedContainer.Runtime.ContainerImageName = ""
			}

			normalize := func(c *containercollection.Container) {
				c.OciConfig = ""
				c.Bundle = ""
				c.Mntns = 0
				c.Netns = 0
				c.CgroupPath = ""
				c.CgroupID = 0
				c.CgroupV1 = ""
				c.CgroupV2 = ""

				c.SandboxId = ""
				c.Runtime.ContainerID = ""
				c.Runtime.ContainerPID = 0
				c.Runtime.ContainerImageDigest = ""
				c.Runtime.ContainerStartedAt = 0

				// Docker can provide different values for ContainerImageName. See `getContainerImageNamefromImage`
				if isDockerRuntime {
					c.Runtime.ContainerImageName = ""
				}
			}

			match.MatchEntries(t, match.JSONSingleArrayMode, output, normalize, expectedContainer)
		},
	}

	RunTestSteps([]TestStep{listContainersCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}

func TestEnrichmentPodLabelNewPod(t *testing.T) {
	if DefaultTestComponent != IgTestComponent {
		t.Skip("Skip running new pod label enrichment test with test component different than ig")
	}

	t.Parallel()

	cn := "test-enrichment-pod-label-new-pod"
	pod := cn
	ns := GenerateTestNamespaceName(pod)

	listContainersCmd := &Command{
		Name:         "RunWatchContainers",
		Cmd:          fmt.Sprintf("ig list-containers -o json --runtimes=%s --runtime-protocol=cri --watch", containerRuntime),
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
							PodLabels: map[string]string{
								"run": cn,
							},
						},
					},
					Runtime: containercollection.RuntimeMetadata{
						BasicRuntimeMetadata: types.BasicRuntimeMetadata{
							RuntimeName:        types.String2RuntimeName(containerRuntime),
							ContainerName:      cn,
							ContainerImageName: "ghcr.io/inspektor-gadget/ci/busybox:latest",
						},
					},
				},
			}

			// Docker can provide different values for ContainerImageName. See `getContainerImageNamefromImage`
			if isDockerRuntime {
				expectedEvent.Container.Runtime.ContainerImageName = ""
			}

			normalize := func(e *containercollection.PubSubEvent) {
				e.Container.OciConfig = ""
				e.Container.Bundle = ""
				e.Container.Mntns = 0
				e.Container.Netns = 0
				e.Container.CgroupPath = ""
				e.Container.CgroupID = 0
				e.Container.CgroupV1 = ""
				e.Container.CgroupV2 = ""
				e.Timestamp = ""

				e.Container.SandboxId = ""
				e.Container.K8s.PodUID = ""
				e.Container.Runtime.ContainerID = ""
				e.Container.Runtime.ContainerPID = 0
				e.Container.Runtime.ContainerImageDigest = ""
				e.Container.Runtime.ContainerStartedAt = 0

				// CRI-O and Docker use a custom container name composed, among
				// other things, by the pod UID. We don't know the pod UID in
				// advance, so we can't match the expected container name.
				// TODO: Create a test for this once we support filtering by k8s
				// container name. See
				// https://github.com/inspektor-gadget/inspektor-gadget/issues/1403.
				if e.Container.Runtime.RuntimeName == ContainerRuntimeCRIO || e.Container.Runtime.RuntimeName == ContainerRuntimeDocker {
					e.Container.Runtime.ContainerName = cn
				}

				// Docker can provide different values for ContainerImageName. See `getContainerImageNamefromImage`
				if isDockerRuntime {
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
		listContainersCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		PodCommand(pod, "ghcr.io/inspektor-gadget/ci/busybox:latest", ns, `["sleep", "inf"]`, ""),
		WaitUntilPodReadyCommand(ns, pod),
		DeleteTestNamespaceCommand(ns),
	}
	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
