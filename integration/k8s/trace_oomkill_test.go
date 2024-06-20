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
	traceoomkillTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/oomkill/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
)

func TestTraceOOMKill(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-oomkill")

	var extraArgs string
	expectedEntry := &traceoomkillTypes.Event{KilledComm: "tail"}

	switch DefaultTestComponent {
	case IgTestComponent:
		extraArgs = fmt.Sprintf("--runtimes=%s", containerRuntime)
		expectedEntry.Event = BuildBaseEvent(ns,
			WithRuntimeMetadata(containerRuntime),
			WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime),
			WithPodLabels("test-pod", ns, isCrioRuntime),
		)
	case InspektorGadgetTestComponent:
		extraArgs = fmt.Sprintf("-n %s", ns)
		expectedEntry.Event = BuildBaseEventK8s(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime))
		expectedEntry.K8s.ContainerName = "test-pod"
	}

	traceOOMKillCmd := &Command{
		Name:         "TraceOomkill",
		Cmd:          fmt.Sprintf("%s trace oomkill -o json %s", DefaultTestComponent, extraArgs),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			normalize := func(e *traceoomkillTypes.Event) {
				e.Timestamp = 0
				e.KilledPid = 0
				e.Pages = 0
				e.TriggeredPid = 0
				e.TriggeredUid = 0
				e.TriggeredGid = 0
				e.TriggeredComm = ""
				e.MountNsID = 0

				normalizeCommonData(&e.CommonData, ns)
			}

			match.MatchAllEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntry)
		},
	}

	limitPodYaml := fmt.Sprintf(`
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
    resources:
      limits:
        memory: "128Mi"
    command: ["/bin/sh", "-c"]
    args:
    - while true; do tail /dev/zero; done
`, ns)

	commands := []TestStep{
		CreateTestNamespaceCommand(ns),
		traceOOMKillCmd,
		SleepForSecondsCommand(2), // wait to ensure ig or kubectl-gadget has started
		&Command{
			Name:           "RunOomkillTestPod",
			Cmd:            fmt.Sprintf("echo '%s' | kubectl apply -f -", limitPodYaml),
			ExpectedRegexp: "pod/test-pod created",
		},
		WaitUntilTestPodReadyOrOOMKilledCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
