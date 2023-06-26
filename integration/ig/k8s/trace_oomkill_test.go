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
	"strings"
	"testing"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	oomkillTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/oomkill/types"
)

func TestTraceOOMKill(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-oomkill")

	traceOOMKillCmd := &Command{
		Name:         "TraceOomkill",
		Cmd:          fmt.Sprintf("ig trace oomkill -o json --runtimes=%s", *containerRuntime),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &oomkillTypes.Event{
				Event:        BuildBaseEvent(ns, WithRuntimeMetadata(*containerRuntime)),
				KilledComm:   "tail",
				TriggeredUid: 1000,
				TriggeredGid: 2000,
			}

			normalize := func(e *oomkillTypes.Event) {
				// Docker and CRI-O use a custom container name composed, among
				// other things, by the pod UID. We don't know the pod UID in
				// advance, so we can't match the exact expected container name.
				prefixContainerName := "k8s_" + "test-pod" + "_" + "test-pod" + "_" + ns + "_"
				if (*containerRuntime == ContainerRuntimeDocker || *containerRuntime == ContainerRuntimeCRIO) &&
					strings.HasPrefix(e.Runtime.ContainerName, prefixContainerName) {
					e.Runtime.ContainerName = "test-pod"
				}

				e.Timestamp = 0
				e.KilledPid = 0
				e.Pages = 0
				e.TriggeredPid = 0
				e.TriggeredComm = ""
				e.MountNsID = 0

				e.Runtime.ContainerID = ""
			}

			return ExpectAllToMatch(output, normalize, expectedEntry)
		},
	}

	limitPodYaml := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: %s
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
    - setuidgid 1000:2000 sh -c "while true; do tail /dev/zero; done"
`, ns)

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		traceOOMKillCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		{
			Name:           "RunOomkillTestPod",
			Cmd:            fmt.Sprintf("echo '%s' | kubectl apply -f -", limitPodYaml),
			ExpectedRegexp: "pod/test-pod created",
		},
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
