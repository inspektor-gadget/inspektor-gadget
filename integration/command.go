// Copyright 2019-2021 The Inspektor Gadget authors
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
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"testing"

	"github.com/kr/pretty"
)

const (
	namespaceLabelKey   string = "scope"
	namespaceLabelValue string = "ig-integration-tests"
)

type command struct {
	// name of the command to be run, used to give information.
	name string

	// cmd is a string of the command which will be run.
	cmd string

	// command is a Cmd object used when we want to start the command, then other
	// do stuff and wait for its completion.
	command *exec.Cmd

	// stdout contains command standard output when started using Startcommand().
	stdout bytes.Buffer

	// stderr contains command standard output when started using Startcommand().
	stderr bytes.Buffer

	// expectedString contains the exact expected output of the command.
	expectedString string

	// expectedRegexp contains a regex used to match against the command output.
	expectedRegexp string

	// cleanup indicates this command is used to clean resource and should not be
	// skipped even if previous commands failed.
	cleanup bool

	// startAndStop indicates this command should first be started then stopped.
	// It corresponds to gadget like execsnoop which wait user to type Ctrl^C.
	startAndStop bool

	// started indicates this command was started.
	// It is only used by command which have startAndStop set.
	started bool
}

var deployInspektorGadget *command = &command{
	name:           "DeployInspektorGadget",
	cmd:            "$KUBECTL_GADGET deploy $GADGET_IMAGE_FLAG | kubectl apply -f -",
	expectedRegexp: "gadget created",
}

var waitUntilInspektorGadgetPodsDeployed *command = &command{
	name: "WaitForGadgetPods",
	cmd: `
	for POD in $(sleep 5; kubectl get pod -n gadget -l k8s-app=gadget -o name) ; do
		kubectl wait --timeout=30s -n gadget --for=condition=ready $POD
		if [ $? -ne 0 ]; then
			kubectl get pod -n gadget
			kubectl describe $POD -n gadget
			exit 1
		fi
	done`,
}

func deploySPO(limitReplicas, bestEffortResourceMgmt bool) *command {
	cmdStr := fmt.Sprintf(`
kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.8.0/cert-manager.yaml
kubectl --namespace cert-manager wait --for condition=ready pod -l app.kubernetes.io/instance=cert-manager
curl https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/v0.4.3/deploy/operator.yaml | \
  if [ %v = true ] ; then
    sed 's/replicas: 3/replicas: 1/' | grep -v cpu:
  else
    cat
  fi | \
  kubectl apply -f -

# Wait for the SPO which will create the rest of the resources.
# Unfortunately, it takes quite a while, hence the long timeouts.
kubectl -n security-profiles-operator wait deploy security-profiles-operator --for condition=available
kubectl -n security-profiles-operator wait pod -l app=security-profiles-operator --for condition=ready

# The SPO-webhook and SPO-daemon are not part of the YAML but created by the SPO.
# We cannot use kubectl-wait before they are created, see also: https://github.com/kubernetes/kubernetes/issues/83242
webhook=false
daemon=false
for i in $(seq 1 120); do
  if [ "$(kubectl get pod -n security-profiles-operator -l app=security-profiles-operator,name=security-profiles-operator-webhook -o go-template='{{len .items}}')" -ge 1 ] ; then
    webhook=true
  fi
  if [ "$(kubectl get pod -n security-profiles-operator -l app=security-profiles-operator,name=spod -o go-template='{{len .items}}')" -ge 1 ] ; then
    daemon=true
  fi

  if [ $webhook = true ] && [ $daemon = true ] ; then
    break
  fi

  sleep 1
done

# If requested, remove the resource management and let Kubernetes use the best-effort
# QoS approach. It is useful on system with limited resources as Minikube on a GH runner.
if [ %v = true ] ; then
  kubectl patch deploy -n security-profiles-operator security-profiles-operator-webhook --type=json \
    -p='[{"op": "remove", "path": "/spec/template/spec/containers/0/resources"}]'
  kubectl patch ds -n security-profiles-operator spod --type=json \
    -p='[{"op": "remove", "path": "/spec/template/spec/containers/0/resources"}, {"op": "remove", "path": "/spec/template/spec/containers/1/resources"}, {"op": "remove", "path": "/spec/template/spec/initContainers/0/resources"}]'

  # Give some time to the pods to be restarted
  sleep 3
fi

# At this point, the webhook and daemon were created, wait til they are ready.
kubectl -n security-profiles-operator wait deploy security-profiles-operator-webhook --for condition=available || \
  (kubectl get pod -n security-profiles-operator ; kubectl get events -n security-profiles-operator ; false)
kubectl rollout status -n security-profiles-operator ds spod --timeout=180s || \
  (kubectl get pod -n security-profiles-operator ; kubectl get events -n security-profiles-operator ; false)
`, limitReplicas, bestEffortResourceMgmt)
	return &command{
		name:           "DeploySecurityProfilesOperator",
		cmd:            cmdStr,
		expectedRegexp: `daemon set "spod" successfully rolled out`,
	}
}

func waitUntilInspektorGadgetPodsInitialized(initialDelay int) *command {
	return &command{
		name: "WaitForInspektorGadgetInit",
		cmd:  fmt.Sprintf("sleep %d", initialDelay),
	}
}

var cleanupInspektorGadget *command = &command{
	name:    "CleanupInspektorGadget",
	cmd:     "$KUBECTL_GADGET undeploy",
	cleanup: true,
}

var cleanupSPO *command = &command{
	name: "RemoveSecurityProfilesOperator",
	cmd: `
	kubectl delete seccompprofile -n security-profiles-operator --all
	kubectl delete -f https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/v0.4.3/deploy/operator.yaml
	kubectl delete -f https://github.com/jetstack/cert-manager/releases/download/v1.8.0/cert-manager.yaml
	`,
	cleanup: true,
}

// createExecCmd creates an exec.Cmd for the command c.cmd and stores it in
// command.command. The exec.Cmd is configured to store the stdout and stderr in
// command.stdout and command.stderr so that we can use them on
// command.verifyOutput().
func (c *command) createExecCmd() {
	cmd := exec.Command("/bin/sh", "-c", c.cmd)

	cmd.Stdout = &c.stdout
	cmd.Stderr = &c.stderr

	// To be able to kill the process of /bin/sh and its child (the process of
	// c.cmd), we need to send the termination signal to their process group ID
	// (PGID). However, child processes get the same PGID as their parents by
	// default, so in order to avoid killing also the integration tests process,
	// we set the fields Setpgid and Pgid of syscall.SysProcAttr before
	// executing /bin/sh. Doing so, the PGID of /bin/sh (and its children)
	// will be set to its process ID, see:
	// https://cs.opensource.google/go/go/+/refs/tags/go1.17.8:src/syscall/exec_linux.go;l=32-34.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: 0}

	c.command = cmd
}

// getInspektorGadgetLogs returns a string with the logs of the gadget pods
func getInspektorGadgetLogs() string {
	var sb strings.Builder

	logCommands := []string{
		"kubectl get pods -n gadget -o wide",
		`for pod in $(kubectl get pods -n gadget -o name); do
			kubectl logs -n gadget $pod;
		done`,
	}

	for _, c := range logCommands {
		cmd := exec.Command("/bin/sh", "-xc", c)
		output, err := cmd.CombinedOutput()
		if err != nil {
			sb.WriteString(fmt.Sprintf("Error: failed to run log command: %s\n", cmd.String()))
			continue
		}
		sb.WriteString(string(output))
	}

	return sb.String()
}

// verifyOutput verifies if the stdout match with the expected regular
// expression and the expected string. If it doesn't, verifyOutput returns and
// error and the gadget pod logs.
func (c *command) verifyOutput() error {
	output := c.stdout.String()

	if c.expectedRegexp != "" {
		r := regexp.MustCompile(c.expectedRegexp)
		if !r.MatchString(output) {
			return fmt.Errorf("output didn't match the expected regexp: %s\n%s",
				c.expectedRegexp, getInspektorGadgetLogs())
		}
	}

	if c.expectedString != "" && output != c.expectedString {
		return fmt.Errorf("output didn't match the expected string: %s\n%v\n%s",
			c.expectedString, pretty.Diff(c.expectedString, output), getInspektorGadgetLogs())
	}

	return nil
}

// kill kills a command by sending SIGKILL because we want to stop the process
// immediatly and avoid that the signal is trapped.
func (c *command) kill() error {
	const sig syscall.Signal = syscall.SIGKILL

	// No need to kill, command has not been executed yet or it already exited
	if c.command == nil || (c.command.ProcessState != nil && c.command.ProcessState.Exited()) {
		return nil
	}

	// Given that we set Setpgid, here we just need to send the PID of /bin/sh
	// (which is the same PGID) as a negative number to syscall.Kill(). As a
	// result, the signal will be received by all the processes with such PGID,
	// in our case, the process of /bin/sh and c.cmd.
	err := syscall.Kill(-c.command.Process.Pid, sig)
	if err != nil {
		return err
	}

	// In some cases, we do not have to wait here because the cmd was executed
	// with Run(), which already waits. On the contrary, in the case it was
	// executed with Start() thus c.started is true, we need to wait indeed.
	if c.started {
		err = c.command.Wait()
		if err == nil {
			return nil
		}

		// Verify if the error is about the signal we just sent. In that case,
		// do not return error, it is what we were expecting.
		var exiterr *exec.ExitError
		if ok := errors.As(err, &exiterr); !ok {
			return err
		}

		waitStatus, ok := exiterr.Sys().(syscall.WaitStatus)
		if !ok {
			return err
		}

		if waitStatus.Signal() != sig {
			return err
		}

		return nil
	}

	return err
}

// runWithoutTest runs the command, this is thought to be used in TestMain().
func (c *command) runWithoutTest() error {
	c.createExecCmd()

	fmt.Printf("Run command(%s):\n%s\n", c.name, c.cmd)
	err := c.command.Run()
	fmt.Printf("Command returned(%s):\n%s\n%s\n",
		c.name, c.stderr.String(), c.stdout.String())

	if err != nil {
		return fmt.Errorf("failed to run command(%s): %w", c.name, err)
	}

	if err = c.verifyOutput(); err != nil {
		return fmt.Errorf("invalid command output(%s): %w", c.name, err)
	}

	return nil
}

// startWithoutTest starts the command, this is thought to be used in TestMain().
func (c *command) startWithoutTest() error {
	if c.started {
		fmt.Printf("Warn(%s): trying to start command but it was already started\n", c.name)
		return nil
	}

	c.createExecCmd()

	fmt.Printf("Start command(%s): %s\n", c.name, c.cmd)
	err := c.command.Start()
	if err != nil {
		return fmt.Errorf("failed to start command(%s): %w", c.name, err)
	}

	c.started = true

	return nil
}

// waitWithoutTest waits for a command that was started with startWithoutTest(),
// this is thought to be used in TestMain().
func (c *command) waitWithoutTest() error {
	if !c.started {
		fmt.Printf("Warn(%s): trying to wait for a command that has not been started yet\n", c.name)
		return nil
	}

	fmt.Printf("Wait for command(%s)\n", c.name)
	err := c.command.Wait()
	fmt.Printf("Command returned(%s):\n%s\n%s\n",
		c.name, c.stderr.String(), c.stdout.String())

	if err != nil {
		return fmt.Errorf("failed to wait for command(%s): %w", c.name, err)
	}

	c.started = false

	return nil
}

// killWithoutTest kills for a command that was started with startWithoutTest()
// or runWithoutTest() and we do not need to verify its output. This is thought
// to be used in TestMain().
func (c *command) killWithoutTest() error {
	fmt.Printf("Kill command(%s)\n", c.name)

	if err := c.kill(); err != nil {
		return fmt.Errorf("failed to kill command(%s): %w", c.name, err)
	}

	return nil
}

// run runs the command on the given as parameter test.
func (c *command) run(t *testing.T) {
	c.createExecCmd()

	if c.startAndStop {
		c.start(t)
		return
	}

	t.Logf("Run command(%s):\n%s\n", c.name, c.cmd)
	err := c.command.Run()
	t.Logf("Command returned(%s):\n%s\n%s\n",
		c.name, c.stderr.String(), c.stdout.String())

	if err != nil {
		t.Fatalf("failed to run command(%s): %s\n", c.name, err)
	}

	err = c.verifyOutput()
	if err != nil {
		t.Fatalf("invalid command output(%s): %s\n", c.name, err)
	}
}

// start starts the command on the given as parameter test, you need to
// wait it using stop().
func (c *command) start(t *testing.T) {
	if c.started {
		t.Logf("Warn(%s): trying to start command but it was already started\n", c.name)
		return
	}

	t.Logf("Start command(%s): %s\n", c.name, c.cmd)
	err := c.command.Start()
	if err != nil {
		t.Fatalf("failed to start command(%s): %s\n", c.name, err)
	}

	c.started = true
}

// stop stops a command previously started with start().
// To do so, it Kill() the process corresponding to this Cmd and then wait for
// its termination.
// Cmd output is then checked with regard to expectedString and expectedRegexp
func (c *command) stop(t *testing.T) {
	if !c.started {
		t.Logf("Warn(%s): trying to stop command but it was not started\n", c.name)
		return
	}

	t.Logf("Stop command(%s)\n", c.name)
	err := c.kill()
	t.Logf("Command returned(%s):\n%s\n%s\n",
		c.name, c.stderr.String(), c.stdout.String())

	if err != nil {
		t.Fatalf("failed to stop command(%s): %s\n", c.name, err)
	}

	err = c.verifyOutput()
	if err != nil {
		t.Fatalf("invalid command output(%s): %s\n", c.name, err)
	}

	c.started = false
}

// busyboxPodRepeatCommand returns a command that creates a pod and runs
// "cmd" each 0.1 seconds inside the pod.
func busyboxPodRepeatCommand(namespace, cmd string) *command {
	cmdStr := fmt.Sprintf("while true; do %s && sleep 0.1; done", cmd)
	return busyboxPodCommand(namespace, cmdStr)
}

// busyboxPodCommand returns a command that creates a pod and runs "cmd" in it.
func busyboxPodCommand(namespace, cmd string) *command {
	cmdStr := fmt.Sprintf(`kubectl apply -f - <<"EOF"
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: %s
  labels:
    run: test-pod
spec:
  restartPolicy: Never
  terminationGracePeriodSeconds: 0
  containers:
  - name: test-pod
    image: busybox
    command: ["/bin/sh", "-c"]
    args:
    - %s
EOF
`, namespace, cmd)

	return &command{
		name:           "RunTestPod",
		cmd:            cmdStr,
		expectedString: "pod/test-pod created\n",
	}
}

// generateTestNamespaceName returns a string which can be used as unique
// namespace.
// The returned value is: namespace_parameter-random_integer.
func generateTestNamespaceName(namespace string) string {
	return fmt.Sprintf("%s-%d", namespace, rand.Int())
}

// createTestNamespaceCommand returns a command which creates a namespace whom
// name is given as parameter.
func createTestNamespaceCommand(namespace string) *command {
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

	return &command{
		name: "Create test namespace",
		cmd:  cmd,
	}
}

// deleteTestNamespaceCommand returns a command which deletes a namespace whom
// name is given as parameter.
func deleteTestNamespaceCommand(namespace string) *command {
	return &command{
		name:           "DeleteTestNamespace",
		cmd:            fmt.Sprintf("kubectl delete ns %s", namespace),
		expectedString: fmt.Sprintf("namespace \"%s\" deleted\n", namespace),
		cleanup:        true,
	}
}

// deleteRemainingNamespacesCommand returns a command which deletes a namespace whom
// name is given as parameter.
func deleteRemainingNamespacesCommand() *command {
	return &command{
		name: "DeleteRemainingTestNamespace",
		cmd: fmt.Sprintf("kubectl delete ns -l %s=%s",
			namespaceLabelKey, namespaceLabelValue),
		cleanup: true,
	}
}

// waitUntilTestPodReadyCommand returns a command which waits until test-pod in
// the given as parameter namespace is ready.
func waitUntilTestPodReadyCommand(namespace string) *command {
	return &command{
		name:           "WaitForTestPod",
		cmd:            fmt.Sprintf("kubectl wait pod --for condition=ready -n %s test-pod", namespace),
		expectedString: "pod/test-pod condition met\n",
	}
}
