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
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"regexp"
	"testing"

	"github.com/kr/pretty"
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
	name:           "Deploy Inspektor Gadget",
	cmd:            "$KUBECTL_GADGET deploy $GADGET_IMAGE_FLAG | kubectl apply -f -",
	expectedRegexp: "gadget created",
}

var waitUntilInspektorGadgetPodsDeployed *command = &command{
	name: "Wait until the gadget pods are started",
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

var waitUntilInspektorGadgetPodsInitialized *command = &command{
	name: "Wait until Inspektor Gadget is initialised",
	cmd:  "uname -a; zgrep BTF /proc/config.gz; sleep 15",
}

var cleanupInspektorGadget *command = &command{
	name:    "cleanup gadget deployment",
	cmd:     "$KUBECTL_GADGET undeploy",
	cleanup: true,
}

// run runs the command on the given as parameter test.
func (c *command) run(t *testing.T) {
	if c.startAndStop {
		if !c.started {
			c.start(t)

			c.started = true
		} else {
			c.stop(t)
		}

		return
	}

	t.Logf("command: %s\n", c.cmd)
	cmd := exec.Command("/bin/sh", "-c", c.cmd)
	output, err := cmd.CombinedOutput()
	actual := string(output)
	t.Logf("command returned:\n%s\n", actual)
	if err != nil {
		t.Fatal(err)
	}

	if c.expectedRegexp != "" {
		r := regexp.MustCompile(c.expectedRegexp)
		if !r.MatchString(actual) {
			t.Fatalf("regexp didn't match: %s\n%s\n", c.expectedRegexp, actual)
		}
	}
	if c.expectedString != "" && actual != c.expectedString {
		t.Fatalf("diff: %v", pretty.Diff(c.expectedString, actual))
	}
}

// runWithoutTest runs the command, this is thought to be used in TestMain().
func (c *command) runWithoutTest() error {
	fmt.Printf("command: %s\n", c.cmd)
	cmd := exec.Command("/bin/sh", "-c", c.cmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, string(output))
		return err
	}

	actual := string(output)
	fmt.Printf("command returned:\n%s\n", actual)

	if c.expectedRegexp != "" {
		r := regexp.MustCompile(c.expectedRegexp)
		if !r.MatchString(actual) {
			return fmt.Errorf("regexp didn't match: %s\n%s\n", c.expectedRegexp, actual)
		}
	}

	if c.expectedString != "" && actual != c.expectedString {
		return fmt.Errorf("diff: %v", pretty.Diff(c.expectedString, actual))
	}

	return nil
}

// start starts the command on the given as parameter test, you need to
// wait it using stop().
func (c *command) start(t *testing.T) {
	t.Logf("Start command: %s\n", c.cmd)
	cmd := exec.Command("/bin/sh", "-c", c.cmd)
	cmd.Stdout = &c.stdout
	cmd.Stderr = &c.stderr

	err := cmd.Start()
	if err != nil {
		t.Fatal(err)
	}

	c.command = cmd
}

// stop stops a command previously started with start().
// To do so, it Kill() the process corresponding to this Cmd and then wait for
// its termination.
// Cmd output is then checked with regard to expectedString and expectedRegexp
func (c *command) stop(t *testing.T) {
	t.Logf("Stop command: %s\n", c.cmd)
	err := c.command.Process.Kill()
	if err != nil {
		t.Fatal(err)
	}

	stdout := c.stdout.String()
	stderr := c.stderr.String()

	if c.expectedRegexp != "" {
		r := regexp.MustCompile(c.expectedRegexp)
		if !r.MatchString(stdout) {
			fmt.Fprintf(os.Stderr, "%s\n", stderr)
			t.Fatalf("regexp didn't match: %s\n%s\n", c.expectedRegexp, stdout)
		}
	}
	if c.expectedString != "" && stdout != c.expectedString {
		fmt.Fprintf(os.Stderr, "%s\n", stderr)
		t.Fatalf("diff: %v", pretty.Diff(c.expectedString, stdout))
	}
}

// busyboxPodCommand returns a string which can be used as command to run a
// busybox pod whom inner command is given as parameter.
func busyboxPodCommand(namespace, cmd string) string {
	return fmt.Sprintf("kubectl run --restart=Never --image=busybox -n %s test-pod -- sh -c '%s'", namespace, cmd)
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
	return &command{
		name:           "Create test namespace",
		cmd:            fmt.Sprintf("kubectl create ns %s", namespace),
		expectedString: fmt.Sprintf("namespace/%s created\n", namespace),
	}
}

// deleteTestNamespaceCommand returns a command which deletes a namespace whom
// name is given as parameter.
func deleteTestNamespaceCommand(namespace string) *command {
	return &command{
		name:           "Delete test namespace",
		cmd:            fmt.Sprintf("kubectl delete ns %s", namespace),
		expectedString: fmt.Sprintf("namespace \"%s\" deleted\n", namespace),
		cleanup:        true,
	}
}

// waitUntilTestPodReadyCommand returns a command which waits until test-pod in
// the given as parameter namespace is ready.
func waitUntilTestPodReadyCommand(namespace string) *command {
	return &command{
		name:           "Wait until test pod ready",
		cmd:            fmt.Sprintf("kubectl wait pod --for condition=ready -n %s test-pod", namespace),
		expectedString: "pod/test-pod condition met\n",
	}
}
