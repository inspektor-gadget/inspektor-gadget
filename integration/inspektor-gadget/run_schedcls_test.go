// Copyright 2024 The Inspektor Gadget authors
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

	"github.com/stretchr/testify/require"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

// TestRunSchedCLS checks that Inspektor Gadget is able to load and attach SchedCLS programs. The
// ci/sched_cls_drop gadget drops packets in ingress and egress. This test tries to reach another
// pod and checks that there was a timeout.
func TestRunSchedCLS(t *testing.T) {
	t.Parallel()

	ns := GenerateTestNamespaceName("test-run-schedcls")

	t.Cleanup(func() {
		commands := []*Command{
			DeleteTestNamespaceCommand(ns),
		}
		RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	commandsPreTest := []*Command{
		CreateTestNamespaceCommand(ns),
		PodCommand("nginx-pod", "nginx", ns, "", ""),
		WaitUntilPodReadyCommand(ns, "nginx-pod"),
	}
	RunTestSteps(commandsPreTest, t)
	nginxIP := GetTestPodIP(t, ns, "nginx-pod")

	cmd := fmt.Sprintf("$KUBECTL_GADGET run %s/ci/sched_cls_drop:%s -n %s", *gadgetRepository, *gadgetTag, ns)
	runSchedCLSCmd := &Command{
		Name:         "StartRunSchedCLS",
		Cmd:          cmd,
		StartAndStop: true,
	}

	commands := []*Command{
		runSchedCLSCmd,
		// Wait until program is attached. TODO: How to avoid hardcoding a delay here?
		SleepForSecondsCommand(5),
		JobCommand("wget", "busybox", ns, "sh", "-c", fmt.Sprintf("wget -T 5 %s || true", nginxIP)),
		WaitUntilJobCompleteCommand(ns, "wget"),
		{
			Name: "ValidateOutput",
			Cmd:  fmt.Sprintf("kubectl logs job.batch/wget -n %s", ns),
			ValidateOutput: func(t *testing.T, output string) {
				// TODO: Another approach will be to test the return code of wget,
				// but it's difficult to implement with the current testing
				// framework.
				require.Contains(t, output, "can't connect to remote host")
			},
		},
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
