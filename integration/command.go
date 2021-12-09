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

	// expectedString contains the exact expected output of the command.
	expectedString string

	// expectedRegexp contains a regex used to match against the command output.
	expectedRegexp string

	// cleanup indicates this command is used to clean resource and should not be
	// skipped even if previous commands failed.
	cleanup bool
}

var deployInspektorGadget *command = &command{
	name:           "Deploy Inspektor Gadget",
	cmd:            "$KUBECTL_GADGET deploy $GADGET_IMAGE_FLAG | kubectl apply -f -",
	expectedRegexp: "gadget created",
}

var waitUntilInspektorGadgetPodsDeployed *command = &command{
	name: "Wait until the gadget pods are started",
	cmd:  "for POD in $(sleep 5 ; kubectl get pod -n kube-system -l k8s-app=gadget -o name) ; do kubectl wait --timeout=30s -n kube-system --for=condition=ready $POD ; done ; kubectl get pod -n kube-system",
}

var waitUntilInspektorGadgetPodsInitialized *command = &command{
	name: "Wait until Inspektor Gadget is initialised",
	cmd:  "sleep 15",
}

var createTestNamespace *command = &command{
	name:           "Create test namespace",
	cmd:            "kubectl create ns test-ns",
	expectedString: "namespace/test-ns created\n",
}

var cleanupTestNamespace *command = &command{
	name:           "cleanup test namespace",
	cmd:            "kubectl delete ns test-ns",
	expectedString: "namespace \"test-ns\" deleted\n",
	cleanup:        true,
}

var cleanupInspektorGadget *command = &command{
	name:           "cleanup gadget deployment",
	cmd:            "$KUBECTL_GADGET deploy $GADGET_IMAGE_FLAG | kubectl delete --wait=false -f -",
	expectedRegexp: "\"gadget\" deleted",
	cleanup:        true,
}

// run runs the command on the given as parameter test.
// It returns true to indicate the command failed, false if it succeeded.
func (c *command) run(t *testing.T) {
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
