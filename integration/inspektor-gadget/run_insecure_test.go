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
	"testing"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestRunInsecure(t *testing.T) {
	ns := GenerateTestNamespaceName("test-run-insecure")

	t.Parallel()

	commandsPreTest := []*Command{
		CreateTestNamespaceCommand(ns),
		PodCommand("registry", "docker.io/library/registry:2", ns, "", ""),
		WaitUntilPodReadyCommand(ns, "registry"),
	}

	RunTestSteps(commandsPreTest, t)

	t.Cleanup(func() {
		commands := []*Command{
			DeleteTestNamespaceCommand(ns),
		}
		RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	registryIP := GetTestPodIP(t, ns, "registry")

	// copy gadget image to insecure registry
	orasCpCmds := []*Command{
		JobCommand("copier", "ghcr.io/oras-project/oras:v1.1.0", ns, "oras", []string{
			"copy",
			"--to-plain-http",
			fmt.Sprintf("%s/trace_open:%s", *gadgetRepository, *gadgetTag),
			fmt.Sprintf("%s:5000/trace_open:%s", registryIP, *gadgetTag),
		}...),
		{
			Name:           "WaitForCopierJob",
			Cmd:            fmt.Sprintf("kubectl wait job --for condition=complete -n %s copier", ns),
			ExpectedString: "job.batch/copier condition met\n",
		},
	}
	RunTestSteps(orasCpCmds, t)

	// TODO: Ideally it should not depend on a real gadget, but we don't have a "test gadget" available yet.
	cmd := fmt.Sprintf("$KUBECTL_GADGET run %s:5000/trace_open:%s -n %s -o json --insecure", registryIP, *gadgetTag, ns)
	runTraceOpen(t, ns, cmd)
}
