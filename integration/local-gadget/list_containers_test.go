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
		Cmd:  fmt.Sprintf("local-gadget list-containers -o json --runtimes=%s", *containerRuntime),
		ExpectedOutputFn: func(output string) error {
			expectedContainer := &containercollection.Container{
				Name:      "test-pod",
				Podname:   "test-pod",
				Runtime:   *containerRuntime,
				Namespace: ns,
			}

			normalize := func(c *containercollection.Container) {
				// TODO: Handle it once we support getting K8s container name for docker
				// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/737
				if *containerRuntime == ContainerRuntimeDocker {
					c.Name = "test-pod"
				}

				c.ID = ""
				c.Pid = 0
				c.OciConfig = nil
				c.Bundle = ""
				c.Mntns = 0
				c.Netns = 0
				c.CgroupPath = ""
				c.CgroupID = 0
				c.CgroupV1 = ""
				c.CgroupV2 = ""
				c.Labels = nil
				c.PodUID = ""
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

	RunCommands(commands, t)
}

func TestListSingleContainer(t *testing.T) {
	t.Parallel()
	prefix := "test-list-single"
	po := fmt.Sprintf("%s-pod", prefix)
	cn := fmt.Sprintf("%s-container", prefix)
	ns := GenerateTestNamespaceName(fmt.Sprintf("%s-namespace", prefix))

	// TODO: Handle it once we support getting K8s container name for docker
	// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/737
	if *containerRuntime == ContainerRuntimeDocker {
		t.Skip("Skip TestListSingleContainer on docker since we don't propagate the Kubernetes pod container name")
	}

	TestPodYaml := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  namespace: %s
  name: %s
spec:
  restartPolicy: Never
  terminationGracePeriodSeconds: 0
  containers:
  - name: %s
    image: busybox
    command: ["/bin/sh", "-c"]
    args:
    - "sleep inf"
`, ns, po, cn)

	listContainersCmd := &Command{
		Name: "RunListSingleContainer",
		Cmd:  fmt.Sprintf("local-gadget list-containers -o json --runtimes=%s --containername=%s", *containerRuntime, cn),
		ExpectedOutputFn: func(output string) error {
			expectedContainer := &containercollection.Container{
				Name:      cn,
				Podname:   po,
				Runtime:   *containerRuntime,
				Namespace: ns,
			}

			normalize := func(c *containercollection.Container) {
				c.ID = ""
				c.Pid = 0
				c.OciConfig = nil
				c.Bundle = ""
				c.Mntns = 0
				c.Netns = 0
				c.CgroupPath = ""
				c.CgroupID = 0
				c.CgroupV1 = ""
				c.CgroupV2 = ""
				c.Labels = nil
				c.PodUID = ""
			}

			return ExpectAllToMatch(output, normalize, expectedContainer)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		{
			Name:           "RunTestListSinglePod",
			Cmd:            fmt.Sprintf("echo '%s' | kubectl apply -f -", TestPodYaml),
			ExpectedRegexp: fmt.Sprintf("pod/%s created", po),
		},
		{
			Name:           "WaitForTestListSinglePod",
			Cmd:            fmt.Sprintf("kubectl wait pod --for condition=ready -n %s %s", ns, po),
			ExpectedString: fmt.Sprintf("pod/%s condition met\n", po),
		},
		listContainersCmd,
		DeleteTestNamespaceCommand(ns),
	}

	RunCommands(commands, t)
}
