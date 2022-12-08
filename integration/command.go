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

package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kr/pretty"
	v1 "k8s.io/api/core/v1"
	k8smeta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
)

const (
	namespaceLabelKey   string = "scope"
	namespaceLabelValue string = "ig-integration-tests"
)

type Command interface {
	Run(*testing.T)
	Start(*testing.T)
	Stop(*testing.T)

	RunWithoutTest() error
	StartWithoutTest() error
	WaitWithoutTest() error
	KillWithoutTest() error

	IsCleanup() bool
	IsStartAndStop() bool
	IsStarted() bool
}

type K8sCommand struct {
	name    string
	runFunc func(*testing.T)
}

func (c *K8sCommand) Run(t *testing.T) {
	t.Logf("Run K8sCommand:\n%s\n", c.name)
	c.runFunc(t)
}
func (c *K8sCommand) Start(*testing.T) {}
func (c *K8sCommand) Stop(*testing.T)  {}

func (c *K8sCommand) RunWithoutTest() error   { return nil }
func (c *K8sCommand) StartWithoutTest() error { return nil }
func (c *K8sCommand) WaitWithoutTest() error  { return nil }
func (c *K8sCommand) KillWithoutTest() error  { return nil }

func (c *K8sCommand) IsCleanup() bool      { return false }
func (c *K8sCommand) IsStartAndStop() bool { return false }
func (c *K8sCommand) IsStarted() bool      { return false }

type CmdCommand struct {
	// Name of the command to be run, used to give information.
	Name string

	// Cmd is a string of the command which will be run.
	Cmd string

	// ExpectedString contains the exact expected output of the command.
	ExpectedString string

	// ExpectedRegexp contains a regex used to match against the command output.
	ExpectedRegexp string

	// ExpectedOutputFn is a function used to verify the output.
	ExpectedOutputFn func(output string) error

	// Cleanup indicates this command is used to clean resource and should not be
	// skipped even if previous commands failed.
	Cleanup bool

	// StartAndStop indicates this command should first be started then stopped.
	// It corresponds to gadget like execsnoop which wait user to type Ctrl^C.
	StartAndStop bool

	// Started indicates this command was Started.
	// It is only used by command which have StartAndStop set.
	Started bool

	// command is a Cmd object used when we want to start the command, then other
	// do stuff and wait for its completion.
	command *exec.Cmd

	// stdout contains command standard output when started using Startcommand().
	stdout bytes.Buffer

	// stderr contains command standard output when started using Startcommand().
	stderr bytes.Buffer
}

func (c *CmdCommand) IsCleanup() bool      { return c.Cleanup }
func (c *CmdCommand) IsStartAndStop() bool { return c.StartAndStop }
func (c *CmdCommand) IsStarted() bool      { return c.Started }

// DeployInspektorGadget deploys inspector gadget in Kubernetes
func DeployInspektorGadget(image, imagePullPolicy string) *CmdCommand {
	cmd := fmt.Sprintf("$KUBECTL_GADGET deploy --image-pull-policy=%s --debug",
		imagePullPolicy)

	if image != "" {
		cmd = cmd + " --image=" + image
	}

	return &CmdCommand{
		Name:           "DeployInspektorGadget",
		Cmd:            cmd,
		ExpectedRegexp: "Inspektor Gadget successfully deployed",
	}
}

func DeploySPO(limitReplicas, patchWebhookConfig, bestEffortResourceMgmt bool) *CmdCommand {
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

# Similar to https://github.com/Azure/AKS/issues/1771 SPO webhook reconcilation doesn't work
# on AKS because of an additional selector. So we patch the SPO-daemon config to respect this selector
# using https://github.com/kubernetes-sigs/security-profiles-operator/blob/main/installation-usage.md#configuring-webhooks.
# SPO issue: https://github.com/kubernetes-sigs/security-profiles-operator/issues/1187
if [ %v = true ] ; then
  kubectl -n security-profiles-operator patch spod spod  --type=merge \
    -p='{"spec":{"webhookOptions":[{"name":"binding.spo.io","namespaceSelector":{"matchExpressions":[{"key":"control-plane","operator":"DoesNotExist"}]}},{"name":"recording.spo.io","namespaceSelector":{"matchExpressions":[{"key":"control-plane","operator":"DoesNotExist"}]}}]}}'
  kubectl -n security-profiles-operator wait spod spod --for condition=ready
fi

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

`, limitReplicas, patchWebhookConfig, bestEffortResourceMgmt)
	return &CmdCommand{
		Name:           "DeploySecurityProfilesOperator",
		Cmd:            cmdStr,
		ExpectedRegexp: `daemon set "spod" successfully rolled out`,
	}
}

// CleanupInspektorGadget cleans up inspector gadget in Kubernetes
var CleanupInspektorGadget *CmdCommand = &CmdCommand{
	Name:    "CleanupInspektorGadget",
	Cmd:     "$KUBECTL_GADGET undeploy",
	Cleanup: true,
}

// CleanupSPO cleans up security profile operator in Kubernetes
var CleanupSPO = []Command{
	&CmdCommand{
		Name: "RemoveSecurityProfilesOperator",
		Cmd: `
		kubectl delete seccompprofile --all --all-namespaces
		kubectl delete -f https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/v0.4.3/deploy/operator.yaml --ignore-not-found
		kubectl delete -f https://github.com/jetstack/cert-manager/releases/download/v1.8.0/cert-manager.yaml --ignore-not-found
		`,
		Cleanup: true,
	},
	&CmdCommand{
		Name: "PatchSecurityProfilesOperatorProfiles",
		Cmd: `
		while true; do
		  # Ensure we have profiles to clean, otherwise just exit.
		  NAMESPACES=$(kubectl get seccompprofile --all-namespaces --no-headers --ignore-not-found -o custom-columns=":metadata.namespace" | uniq)
		  if [ -z $NAMESPACES ]; then
		    break
		  fi
 
		  # Patch profiles in each namespace, ignore any errors since it can already be deleted.
		  for NAMESPACE in $NAMESPACES; do
		    PROFILES=$(kubectl get seccompprofile --namespace $NAMESPACE -o name)
		    for PROFILE in $PROFILES; do
		      kubectl patch $PROFILE -n $NAMESPACE -p '{"metadata":{"finalizers":null}}' --type=merge || true
		    done
		  done

		  # Give some time before starting next cycle.
		  sleep 1
		done
		`,
		Cleanup: true,
	},
}

// RunCommands is used to run a list of commands with stopping/clean up logic.
func RunCommands(cmds []Command, t *testing.T) {
	// defer all cleanup commands so we are sure to exit clean whatever
	// happened
	defer func() {
		for _, cmd := range cmds {
			if cmd.IsCleanup() {
				cmd.Run(t)
			}
		}
	}()

	// defer stopping commands
	defer func() {
		for _, cmd := range cmds {
			if cmd.IsStartAndStop() && cmd.IsStarted() {
				// Wait a bit before stopping the command.
				time.Sleep(10 * time.Second)
				cmd.Stop(t)
			}
		}
	}()

	// run all commands but cleanup ones
	for _, cmd := range cmds {
		if cmd.IsCleanup() {
			continue
		}

		cmd.Run(t)
	}
}

// createExecCmd creates an exec.Cmd for the command c.Cmd and stores it in
// CmdCommand.command. The exec.Cmd is configured to store the stdout and stderr in
// CmdCommand.stdout and CmdCommand.stderr so that we can use them on
// CmdCommand.verifyOutput().
func (c *CmdCommand) createExecCmd() {
	cmd := exec.Command("/bin/sh", "-c", c.Cmd)

	cmd.Stdout = &c.stdout
	cmd.Stderr = &c.stderr

	// To be able to kill the process of /bin/sh and its child (the process of
	// c.Cmd), we need to send the termination signal to their process group ID
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
func (c *CmdCommand) verifyOutput() error {
	output := c.stdout.String()

	if c.ExpectedRegexp != "" {
		r := regexp.MustCompile(c.ExpectedRegexp)
		if !r.MatchString(output) {
			return fmt.Errorf("output didn't match the expected regexp: %s\n%s",
				c.ExpectedRegexp, getInspektorGadgetLogs())
		}
	}

	if c.ExpectedString != "" && output != c.ExpectedString {
		return fmt.Errorf("output didn't match the expected string: %s\n%v\n%s",
			c.ExpectedString, pretty.Diff(c.ExpectedString, output), getInspektorGadgetLogs())
	}

	if c.ExpectedOutputFn != nil {
		if err := c.ExpectedOutputFn(output); err != nil {
			return fmt.Errorf("verifying output with custom function: %w\n%s",
				err, getInspektorGadgetLogs())
		}
	}

	return nil
}

// kill kills a command by sending SIGKILL because we want to stop the process
// immediatly and avoid that the signal is trapped.
func (c *CmdCommand) kill() error {
	const sig syscall.Signal = syscall.SIGKILL

	// No need to kill, command has not been executed yet or it already exited
	if c.command == nil || (c.command.ProcessState != nil && c.command.ProcessState.Exited()) {
		return nil
	}

	// Given that we set Setpgid, here we just need to send the PID of /bin/sh
	// (which is the same PGID) as a negative number to syscall.Kill(). As a
	// result, the signal will be received by all the processes with such PGID,
	// in our case, the process of /bin/sh and c.Cmd.
	err := syscall.Kill(-c.command.Process.Pid, sig)
	if err != nil {
		return err
	}

	// In some cases, we do not have to wait here because the Cmd was executed
	// with Run(), which already waits. On the contrary, in the case it was
	// executed with Start() thus c.Started is true, we need to wait indeed.
	if c.Started {
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

// RunWithoutTest runs the CmdCommand, this is thought to be used in TestMain().
func (c *CmdCommand) RunWithoutTest() error {
	c.createExecCmd()

	fmt.Printf("run command(%s):\n%s\n", c.Name, c.Cmd)
	err := c.command.Run()
	fmt.Printf("Command returned(%s):\n%s\n%s\n",
		c.Name, c.stderr.String(), c.stdout.String())

	if err != nil {
		return fmt.Errorf("failed to run command(%s): %w", c.Name, err)
	}

	if err = c.verifyOutput(); err != nil {
		return fmt.Errorf("invalid command output(%s): %w", c.Name, err)
	}

	return nil
}

// StartWithoutTest starts the CmdCommand, this is thought to be used in TestMain().
func (c *CmdCommand) StartWithoutTest() error {
	if c.Started {
		fmt.Printf("Warn(%s): trying to start command but it was already Started\n", c.Name)
		return nil
	}

	c.createExecCmd()

	fmt.Printf("Start command(%s): %s\n", c.Name, c.Cmd)
	err := c.command.Start()
	if err != nil {
		return fmt.Errorf("failed to start command(%s): %w", c.Name, err)
	}

	c.Started = true

	return nil
}

// WaitWithoutTest waits for a CmdCommand that was started with StartWithoutTest(),
// this is thought to be used in TestMain().
func (c *CmdCommand) WaitWithoutTest() error {
	if !c.Started {
		fmt.Printf("Warn(%s): trying to wait for a command that has not been Started yet\n", c.Name)
		return nil
	}

	fmt.Printf("Wait for command(%s)\n", c.Name)
	err := c.command.Wait()
	fmt.Printf("Command returned(%s):\n%s\n%s\n",
		c.Name, c.stderr.String(), c.stdout.String())

	if err != nil {
		return fmt.Errorf("failed to wait for command(%s): %w", c.Name, err)
	}

	c.Started = false

	return nil
}

// KillWithoutTest kills a CmdCommand started with StartWithoutTest()
// or RunWithoutTest() and we do not need to verify its output. This is thought
// to be used in TestMain().
func (c *CmdCommand) KillWithoutTest() error {
	fmt.Printf("Kill command(%s)\n", c.Name)

	if err := c.kill(); err != nil {
		return fmt.Errorf("failed to kill command(%s): %w", c.Name, err)
	}

	return nil
}

// Run runs the CmdCommand on the given as parameter test.
func (c *CmdCommand) Run(t *testing.T) {
	c.createExecCmd()

	if c.StartAndStop {
		c.Start(t)
		return
	}

	t.Logf("Run command(%s):\n%s\n", c.Name, c.Cmd)
	err := c.command.Run()
	t.Logf("Command returned(%s):\n%s\n%s\n",
		c.Name, c.stderr.String(), c.stdout.String())

	if err != nil {
		t.Fatalf("failed to run command(%s): %s\n", c.Name, err)
	}

	err = c.verifyOutput()
	if err != nil {
		t.Fatalf("invalid command output(%s): %s\n", c.Name, err)
	}
}

// Start starts the CmdCommand on the given as parameter test, you need to
// wait it using Stop().
func (c *CmdCommand) Start(t *testing.T) {
	if c.Started {
		t.Logf("Warn(%s): trying to start command but it was already Started\n", c.Name)
		return
	}

	t.Logf("Start command(%s): %s\n", c.Name, c.Cmd)
	err := c.command.Start()
	if err != nil {
		t.Fatalf("failed to start command(%s): %s\n", c.Name, err)
	}

	c.Started = true
}

// Stop stops a CmdCommand previously started with Start().
// To do so, it Kill() the process corresponding to this Cmd and then wait for
// its termination.
// Cmd output is then checked with regard to ExpectedString and ExpectedRegexp
func (c *CmdCommand) Stop(t *testing.T) {
	if !c.Started {
		t.Logf("Warn(%s): trying to stop command but it was not Started\n", c.Name)
		return
	}

	t.Logf("Stop command(%s)\n", c.Name)
	err := c.kill()
	t.Logf("Command returned(%s):\n%s\n%s\n",
		c.Name, c.stderr.String(), c.stdout.String())

	if err != nil {
		t.Fatalf("failed to stop command(%s): %s\n", c.Name, err)
	}

	err = c.verifyOutput()
	if err != nil {
		t.Fatalf("invalid command output(%s): %s\n", c.Name, err)
	}

	c.Started = false
}

// PodCommand returns a Command that starts a pid with a specified image, command and args
func PodCommand(podname, image, namespace string, command, commandArgs []string) *K8sCommand {
	return &K8sCommand{
		name: fmt.Sprintf("Creating pod %s", podname),
		runFunc: func(t *testing.T) {
			k8sClient, err := k8sutil.NewClientsetFromConfigFlags(utils.KubernetesConfigFlags)
			if err != nil {
				t.Fatalf("Creating pod (%s): %s", podname, commonutils.WrapInErrSetupK8sClient(err).Error())
				return
			}

			containerConfig := v1.Container{
				Name:    podname,
				Image:   image,
				Command: command,
				Args:    commandArgs,
			}

			gracedPeriod := int64(0)
			podSpec := v1.PodSpec{
				RestartPolicy:                 v1.RestartPolicyNever,
				TerminationGracePeriodSeconds: &gracedPeriod,
				Containers:                    []v1.Container{containerConfig},
			}

			objectMeta := k8smeta.ObjectMeta{
				Name:      podname,
				Namespace: namespace,
				Labels: map[string]string{
					"run": podname,
				},
			}

			podConfig := v1.Pod{
				ObjectMeta: objectMeta,
				Spec:       podSpec,
			}

			podClient := k8sClient.CoreV1().Pods(namespace)
			// First returned variable is the pod. Maybe we could use it later?
			_, err = podClient.Create(context.TODO(), &podConfig, k8smeta.CreateOptions{})

			if err != nil {
				t.Fatalf("Creating pod (%s): %s\n", podname, err.Error())
				return
			}
		},
	}
}

// BusyboxPodRepeatCommand returns a CmdCommand that creates a pod and runs
// "cmd" each 0.1 seconds inside the pod.
func BusyboxPodRepeatCommand(namespace, cmd string) *K8sCommand {
	cmdStr := fmt.Sprintf("while true; do %s ; sleep 0.1; done", cmd)
	return BusyboxPodCommand(namespace, cmdStr)
}

// BusyboxPodCommand returns a Command that creates a pod and runs "cmd" in it.
func BusyboxPodCommand(namespace, cmd string) *K8sCommand {
	return PodCommand("test-pod", "busybox", namespace, []string{"/bin/sh", "-c"}, []string{cmd})
}

// GenerateTestNamespaceName returns a string which can be used as unique
// namespace.
// The returned value is: namespace_parameter-random_integer.
func GenerateTestNamespaceName(namespace string) string {
	return fmt.Sprintf("%s-%d", namespace, rand.Int())
}

// CreateTestNamespaceCommand returns a CmdCommand which creates a namespace whom
// name is given as parameter.
func CreateTestNamespaceCommand(namespace string) *CmdCommand {
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

	return &CmdCommand{
		Name: "Create test namespace",
		Cmd:  cmd,
	}
}

// CreateTestNamespaceCommandThroughAPI returns a CmdCommand which creates a namespace whom
// name is given as parameter.
// Still a todo
func CreateTestNamespaceCommandThroughAPI(namespace string) *K8sCommand {
	return &K8sCommand{
		name: fmt.Sprintf("Creating namespace %s", namespace),
		runFunc: func(t *testing.T) {
			k8sClient, err := k8sutil.NewClientsetFromConfigFlags(utils.KubernetesConfigFlags)
			if err != nil {
				t.Fatalf("creating namespace %s: %s", namespace, commonutils.WrapInErrSetupK8sClient(err).Error())
				return
			}
			objectMeta := k8smeta.ObjectMeta{
				Name: namespace,
				Labels: map[string]string{
					namespaceLabelKey: namespaceLabelValue,
				},
			}

			nsConfig := v1.Namespace{
				ObjectMeta: objectMeta,
			}

			ns, err := k8sClient.CoreV1().Namespaces().Create(context.TODO(), &nsConfig, k8smeta.CreateOptions{})
			if err != nil {
				t.Fatalf("creating namespace %s: %s", namespace, err.Error())
				return
			}

			timeout := 15
			for i := 0; i < timeout; i++ {
				if ns.Status.Phase == v1.NamespaceActive {
					break
				}
				time.Sleep(1 * time.Second)
			}
			if ns.Status.Phase != v1.NamespaceActive {
				t.Fatalf("namespace %s was not active after %d seconds", namespace, timeout)
			}
		},
	}
}

// DeleteTestNamespaceCommand returns a CmdCommand which deletes a namespace whom
// name is given as parameter.
func DeleteTestNamespaceCommand(namespace string) *CmdCommand {
	return &CmdCommand{
		Name:           "DeleteTestNamespace",
		Cmd:            fmt.Sprintf("kubectl delete ns %s", namespace),
		ExpectedString: fmt.Sprintf("namespace \"%s\" deleted\n", namespace),
		Cleanup:        true,
	}
}

// DeleteRemainingNamespacesCommand returns a CmdCommand which deletes a namespace whom
// name is given as parameter.
func DeleteRemainingNamespacesCommand() *CmdCommand {
	return &CmdCommand{
		Name: "DeleteRemainingTestNamespace",
		Cmd: fmt.Sprintf("kubectl delete ns -l %s=%s",
			namespaceLabelKey, namespaceLabelValue),
		Cleanup: true,
	}
}

// WaitUntilPodReadyCommand returns a CmdCommand which waits until pod with the specified name in
// the given as parameter namespace is ready.
func WaitUntilPodReadyCommand(namespace string, podname string) *K8sCommand {
	return &K8sCommand{
		name: fmt.Sprintf("Waiting for pod %s", podname),
		runFunc: func(t *testing.T) {
			k8sClient, err := k8sutil.NewClientsetFromConfigFlags(utils.KubernetesConfigFlags)
			if err != nil {
				t.Fatal(commonutils.WrapInErrSetupK8sClient(err).Error())
				return
			}

			podClient := k8sClient.CoreV1().Pods(namespace)

			opts := k8smeta.ListOptions{
				FieldSelector: fmt.Sprintf("metadata.name=%s", podname),
			}
			watcher, err := podClient.Watch(context.TODO(), opts)
			if err != nil {
				t.Fatalf("Adding watch for pod (%s): %s\n", podname, err.Error())
				return
			}
			defer watcher.Stop()

			isReady := func(conditions []v1.PodCondition) bool {
				for _, condition := range conditions {
					if condition.Type == v1.PodReady {
						return condition.Status == v1.ConditionTrue
					}
				}
				return false
			}

			podList, err := podClient.List(context.TODO(), opts)
			if err != nil {
				t.Fatal(commonutils.WrapInErrListPods(err).Error())
				return
			} else if len(podList.Items) > 1 {
				t.Fatalf("Found %d pods with name %s instead of 1", len(podList.Items), podname)
				return
			} else if len(podList.Items) == 1 {
				// Check after .Watch(...) so we do not miss an event
				if isReady(podList.Items[0].Status.Conditions) {
					return
				}
			}

			for event := range watcher.ResultChan() {
				switch event.Type {
				case watch.Added:
				case watch.Modified:
					pod := event.Object.(*v1.Pod)

					if isReady(pod.Status.Conditions) {
						return
					}
				case watch.Error:
				default:
					t.Fatalf("Unknown event while waiting for pod %s", podname)
					return
				}
			}
			t.Fatalf("Timeout waiting for pod %s", podname)
		},
	}
}

// WaitUntilTestPodReadyCommand returns a CmdCommand which waits until test-pod in
// the given as parameter namespace is ready.
func WaitUntilTestPodReadyCommand(namespace string) *K8sCommand {
	return WaitUntilPodReadyCommand(namespace, "test-pod")
}

// SleepForSecondsCommand returns a Command which sleeps for given seconds
func SleepForSecondsCommand(seconds int) *CmdCommand {
	return &CmdCommand{
		Name: "SleepForSeconds",
		Cmd:  fmt.Sprintf("sleep %d", seconds),
	}
}
