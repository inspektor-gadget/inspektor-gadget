// Copyright 2023 The Inspektor Gadget authors
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
	"os"
	"testing"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestRunInsecure(t *testing.T) {
	if DefaultTestComponent != IgTestComponent {
		t.Skip("Skip running test with test component different than ig")
	}

	ns := GenerateTestNamespaceName("test-run-insecure")

	t.Parallel()

	commandsPreTest := []TestStep{
		CreateTestNamespaceCommand(ns),
		PodCommand("registry", "docker.io/library/registry:2", ns, "", ""),
		WaitUntilPodReadyCommand(ns, "registry"),
	}

	RunTestSteps(commandsPreTest, t)

	t.Cleanup(func() {
		commands := []TestStep{
			DeleteTestNamespaceCommand(ns),
		}
		RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	registry := GetTestPodIP(t, ns, "registry") + ":5000"

	// copy gadget image to insecure registry
	orasCpCmds := []TestStep{
		JobCommand("copier", "ghcr.io/oras-project/oras:v1.1.0", ns,
			"oras",
			"copy",
			"--to-plain-http",
			fmt.Sprintf("%s/trace_open:%s", *gadgetRepository, *gadgetTag),
			fmt.Sprintf("%s/trace_open:%s", registry, *gadgetTag),
		),
		WaitUntilJobCompleteCommand(ns, "copier"),
	}
	RunTestSteps(orasCpCmds, t)

	err := os.Setenv("IG_EXPERIMENTAL", "true")
	if err != nil {
		t.Fatalf("setting IG_EXPERIMENTAL: %v\n", err)
	}

	// TODO: Ideally it should not depend on a real gadget, but we don't have a "test gadget" available yet.
	// As the image was not signed, we need to set --verify-image=false.
	cmd := fmt.Sprintf("ig run --verify-image=false %s/trace_open:%s -o json --insecure-registries %s --timeout 2",
		registry, *gadgetTag, registry)

	// run the gadget without verifying its output as we only need to check if it runs
	traceOpenCmd := &Command{
		Name: "StartRunTraceOpenGadget",
		Cmd:  cmd,
	}
	RunTestSteps([]TestStep{traceOpenCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))

	err = os.Setenv("IG_EXPERIMENTAL", "false")
	if err != nil {
		t.Fatalf("resetting IG_EXPERIMENTAL: %v\n", err)
	}
}
