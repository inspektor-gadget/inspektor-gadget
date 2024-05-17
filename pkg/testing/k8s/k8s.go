// Copyright 2022-2024 The Inspektor Gadget authors
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

package k8s

import (
	"fmt"
	"math/rand"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/command"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
)

const (
	namespaceLabelKey   string = "scope"
	namespaceLabelValue string = "ig-integration-tests"
)

var (
	seed int64      = time.Now().UTC().UnixNano()
	r    *rand.Rand = rand.New(rand.NewSource(seed))
)

// PodCommand returns a Command that starts a pod with a specified image, command and args
func PodCommand(t *testing.T, podname, image, namespace, cmd, commandArgs string) *command.Command {
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
		ValidateOutput: match.ExpectStringToMatch(t, fmt.Sprintf("pod/%s created\n", podname)),
	}
}

// BusyboxPodRepeatCommand returns a Command that creates a pod and runs
// "cmd" each 0.1 seconds inside the pod.
func BusyboxPodRepeatCommand(t *testing.T, namespace, cmd string) *command.Command {
	cmdStr := fmt.Sprintf("while true; do %s ; sleep 0.1; done", cmd)
	return BusyboxPodCommand(t, namespace, cmdStr)
}

// BusyboxPodCommand returns a Command that creates a pod and runs "cmd" in it.
func BusyboxPodCommand(t *testing.T, namespace, cmd string) *command.Command {
	return PodCommand(t, "test-pod", "busybox", namespace, `["/bin/sh", "-c"]`, cmd)
}

// GenerateTestNamespaceName returns a string which can be used as unique
// namespace.
// The returned value is: namespace_parameter-random_integer.
func GenerateTestNamespaceName(namespace string) string {
	return fmt.Sprintf("%s-%d", namespace, r.Int())
}

// CreateTestNamespaceCommand returns a Command which creates a namespace whom
// name is given as parameter.
func CreateTestNamespaceCommand(namespace string) *command.Command {
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

// DeleteTestNamespaceCommand returns a Command which deletes a namespace whom
// name is given as parameter.
// Must be used with t.Cleanup().
func DeleteTestNamespaceCommand(t *testing.T, namespace string) *command.Command {
	return &command.Command{
		Name:           "DeleteTestNamespace",
		Cmd:            exec.Command("/bin/sh", "-c", fmt.Sprintf("kubectl delete ns %s", namespace)),
		ValidateOutput: match.ExpectStringToMatch(t, fmt.Sprintf("namespace \"%s\" deleted\n", namespace)),
	}
}

// WaitUntilPodReadyCommand returns a Command which waits until pod with the specified name in
// the given as parameter namespace is ready.
func WaitUntilPodReadyCommand(t *testing.T, namespace string, podname string) *command.Command {
	return &command.Command{
		Name:           "WaitForTestPod",
		Cmd:            exec.Command("/bin/sh", "-c", fmt.Sprintf("kubectl wait pod --for condition=ready -n %s %s", namespace, podname)),
		ValidateOutput: match.ExpectStringToMatch(t, fmt.Sprintf("pod/%s condition met\n", podname)),
	}
}

// WaitUntilTestPodReadyCommand returns a Command which waits until test-pod in
// the given as parameter namespace is ready.
func WaitUntilTestPodReadyCommand(t *testing.T, namespace string) *command.Command {
	return WaitUntilPodReadyCommand(t, namespace, "test-pod")
}

// SleepForSecondsCommand returns a Command which sleeps for given seconds
func SleepForSecondsCommand(seconds int) *command.Command {
	return &command.Command{
		Name: "SleepForSeconds",
		Cmd:  exec.Command("/bin/sh", "-c", fmt.Sprintf("sleep %d", seconds)),
	}
}

// PrintLogsFn returns a function that print logs in case the test fails.
func PrintLogsFn(namespaces ...string) func(t *testing.T) {
	return func(t *testing.T) {
		if !t.Failed() {
			return
		}

		t.Logf("Inspektor Gadget pod logs:")
		t.Logf(getPodLogs("gadget"))

		for _, ns := range namespaces {
			t.Logf("Logs in namespace %s:", ns)
			t.Logf(getPodLogs(ns))
		}
	}
}

// getPodLogs returns a string with the logs of all pods in namespace ns
func getPodLogs(ns string) string {
	var sb strings.Builder
	logCommands := []string{
		fmt.Sprintf("kubectl get pods -n %s -o wide", ns),
		fmt.Sprintf(`for pod in $(kubectl get pods -n %[1]s -o name); do
			kubectl logs -n %[1]s $pod --previous;
			kubectl logs -n %[1]s $pod;
		done`, ns),
	}

	for _, c := range logCommands {
		cmd := exec.Command("/bin/sh", "-xc", c)
		output, err := cmd.CombinedOutput()
		if err != nil {
			sb.WriteString(fmt.Sprintf("Error: failed to run log command: %s, %s\n", cmd.String(), err))
			continue
		}
		sb.WriteString(string(output))
	}

	return sb.String()
}
