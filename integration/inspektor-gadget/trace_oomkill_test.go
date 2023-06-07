// Copyright 2019-2022 The Inspektor Gadget authors
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

	traceoomkillTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/oomkill/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestTraceOOMKill(t *testing.T) {
	ns := GenerateTestNamespaceName("test-trace-oomkill")

	t.Parallel()

	traceOomkillCmd := &Command{
		Name:         "StartOomkilGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace oomkill -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &traceoomkillTypes.Event{
				Event:        BuildBaseEvent(ns),
				KilledComm:   "tail",
				TriggeredUid: 1000,
				TriggeredGid: 2000,
			}
			expectedEntry.K8s.Container = "test-pod-container"

			normalize := func(e *traceoomkillTypes.Event) {
				e.Timestamp = 0
				e.KilledPid = 0
				e.Pages = 0
				e.TriggeredPid = 0
				e.TriggeredComm = ""
				e.MountNsID = 0

				e.K8s.Node = ""
				// TODO: Verify container runtime and container name
				e.Runtime = types.BasicRuntimeMetadata{}
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
  - name: test-pod-container
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
		traceOomkillCmd,
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
