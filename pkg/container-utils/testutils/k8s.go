// Copyright 2019-2024 The Inspektor Gadget authors
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

package testutils

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/command"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
)

func NewK8sContainer(name, cmd string, options ...Option) Container {
	c := &K8sContainer{
		containerSpec: containerSpec{
			name:    name,
			cmd:     cmd,
			options: defaultContainerOptions(),
		},
	}
	for _, o := range options {
		o(c.options)
	}
	return c
}

type K8sContainer struct {
	containerSpec

	// additional fields would be added when using golang api
}

// TODO:later on:use the golang api directly

func (c *K8sContainer) Run(t *testing.T) {
	c.Start(t)
	c.Stop(t)
}

func (c *K8sContainer) Start(t *testing.T) {
	// TODO: handle pid, portBindings.

	igtesting.RunTestSteps([]igtesting.TestStep{
		createTestNamespaceCommand(c.options.namespace),
		podCommand(t, c.name, c.options.image, c.options.namespace, `["/bin/sh", "-c"]`, c.cmd),
		sleepForSecondsCommand(2),
		waitUntilPodReadyCommand(t, c.options.namespace, c.name),
	}, t)

	c.id = getContainerID(t, c.name, c.options.namespace)
	c.ip = getPodIP(t, c.name, c.options.namespace)
	c.started = true
}

func (c *K8sContainer) Stop(t *testing.T) {
	igtesting.RunTestSteps([]igtesting.TestStep{
		deletePodCommand(t, c.name, c.options.namespace),
		deleteTestNamespaceCommand(t, c.options.namespace),
	}, t)

	c.started = false
}

const (
	namespaceLabelKey   string = "scope"
	namespaceLabelValue string = "ig-integration-tests"
)

// podCommand returns a Command that starts a pod with a specified image, command and args
func podCommand(t *testing.T, podname, image, namespace, cmd, commandArgs string) *command.Command {
	cmdLine := ""
	if cmd != "" {
		cmdLine = fmt.Sprintf("\n    command: %s", cmd)
	}

	commandArgsLine := ""
	if commandArgs != "" {
		commandArgsLine = fmt.Sprintf("\n    args:\n    - %s", commandArgs)
	}

	cmdStr := fmt.Sprintf(`kubectl apply -f - <<"EOF"
apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
  labels:
    run: %s
spec:
  restartPolicy: Never
  terminationGracePeriodSeconds: 0
  containers:
  - name: %s
    image: %s%s%s
EOF
`, podname, namespace, podname, podname, image, cmdLine, commandArgsLine)

	return &command.Command{
		Name:           fmt.Sprintf("Run %s", podname),
		Cmd:            exec.Command("/bin/sh", "-c", cmdStr),
		StartAndStop:   true,
		ValidateOutput: match.EqualString(t, fmt.Sprintf("pod/%s created\n", podname)),
	}
}

// deletePodCommand returns a Command which deletes a pod whom
// name is given as parameter.
func deletePodCommand(t *testing.T, podname, namespace string) *command.Command {
	return &command.Command{
		Name:           fmt.Sprintf("Delete %s", podname),
		Cmd:            exec.Command("/bin/sh", "-c", fmt.Sprintf("kubectl delete -n=%s pod %s", namespace, podname)),
		ValidateOutput: match.EqualString(t, fmt.Sprintf("pod \"%s\" deleted\n", podname)),
	}
}

// createTestNamespaceCommand returns a Command which creates a namespace whom
// name is given as parameter.
func createTestNamespaceCommand(namespace string) *command.Command {
	cmd := fmt.Sprintf(`kubectl apply -f - <<"EOF"
apiVersion: v1
kind: Namespace
metadata:
  name: %s
  labels: {"%s": "%s"}
EOF
while true; do
  kubectl -n %s get serviceaccount default
  if [ $? -eq 0 ]; then
    break
  fi
  sleep 1
done
	`, namespace, namespaceLabelKey, namespaceLabelValue, namespace)

	return &command.Command{
		Name: "Create test namespace",
		Cmd:  exec.Command("/bin/sh", "-c", cmd),
	}
}

// deleteTestNamespaceCommand returns a Command which deletes a namespace whom
// name is given as parameter.
func deleteTestNamespaceCommand(t *testing.T, namespace string) *command.Command {
	return &command.Command{
		Name:           "DeleteTestNamespace",
		Cmd:            exec.Command("/bin/sh", "-c", fmt.Sprintf("kubectl delete ns %s", namespace)),
		ValidateOutput: match.EqualString(t, fmt.Sprintf("namespace \"%s\" deleted\n", namespace)),
	}
}

// waitUntilPodReadyCommand returns a Command which waits until pod with the specified name in
// the given as parameter namespace is ready.
func waitUntilPodReadyCommand(t *testing.T, namespace string, podname string) *command.Command {
	return &command.Command{
		Name:           "WaitForTestPod",
		Cmd:            exec.Command("/bin/sh", "-c", fmt.Sprintf("kubectl wait pod --for condition=ready -n %s %s", namespace, podname)),
		ValidateOutput: match.EqualString(t, fmt.Sprintf("pod/%s condition met\n", podname)),
	}
}

// sleepForSecondsCommand returns a Command which sleeps for given seconds
func sleepForSecondsCommand(seconds int) *command.Command {
	return &command.Command{
		Name: "SleepForSeconds",
		Cmd:  exec.Command("/bin/sh", "-c", fmt.Sprintf("sleep %d", seconds)),
	}
}

func getContainerID(t *testing.T, podName, namespace string) string {
	cmd := exec.Command("kubectl", "get", "pod", podName, "--namespace", namespace, "-o", "jsonpath={.status.containerStatuses[0].containerID}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	r, err := cmd.Output()
	require.NoError(t, err, "getting container id: %s", stderr.String())

	ret := string(r)
	parts := strings.Split(ret, "/")
	require.GreaterOrEqual(t, len(parts), 1, "unexpected container id")
	return parts[len(parts)-1]
}

func getPodIP(t *testing.T, podName, namespace string) string {
	cmd := exec.Command("kubectl", "-n", namespace, "get", "pod", podName, "-o", "jsonpath={.status.podIP}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	r, err := cmd.Output()
	require.NoError(t, err, "getting pod ip: %s", stderr.String())
	return string(r)
}
