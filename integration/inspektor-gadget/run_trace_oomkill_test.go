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

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func runTraceOOMKill(t *testing.T, ns string, cmd string) {
	// TODO: Handle it once we support getting container image name from docker
	isDockerRuntime := IsDockerRuntime(t)

	traceOOMKillCmd := &Command{
		Name:         "StartRunTraceOOMKillGadget",
		Cmd:          cmd,
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedBaseJsonObj := RunEventToObj(t, &types.Event{
				CommonData: BuildCommonDataK8s(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)),
			})

			expectedTraceOOMKillJsonObj := map[string]interface{}{
				"fpid":      0,
				"fuid":      0,
				"fgid":      0,
				"tpid":      0,
				"pages":     0,
				"mntns_id":  0,
				"timestamp": "",
				"fcomm":     "",
				"tcomm":     "tail",
			}

			expectedJsonObj := MergeJsonObjs(t, expectedBaseJsonObj, expectedTraceOOMKillJsonObj)

			normalize := func(m map[string]interface{}) {
				SetEventK8sNode(m, "")

				// TODO: Verify container runtime and container name
				SetEventRuntimeName(m, "")
				SetEventRuntimeContainerID(m, "")
				SetEventRuntimeContainerName(m, "")

				m["fcomm"] = ""
				m["fpid"] = uint32(0)
				m["fuid"] = uint32(0)
				m["fgid"] = uint32(0)
				m["tpid"] = uint32(0)
				m["pages"] = uint32(0)
				m["mntns_id"] = 0
				m["timestamp"] = ""
			}

			ExpectEntriesToMatchObj(t, output, normalize, expectedJsonObj)
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
    - while true; do tail /dev/zero; done
`, ns)

	commands := []TestStep{
		traceOOMKillCmd,
		&Command{
			Name:           "RunOomkillTestPod",
			Cmd:            fmt.Sprintf("echo '%s' | kubectl apply -f -", limitPodYaml),
			ExpectedRegexp: "pod/test-pod created",
		},
		WaitUntilTestPodReadyOrOOMKilledCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}

func TestRunTraceOOMKill(t *testing.T) {
	ns := GenerateTestNamespaceName("test-run-trace-oomkill")

	t.Parallel()

	commandsPreTest := []TestStep{
		CreateTestNamespaceCommand(ns),
	}

	RunTestSteps(commandsPreTest, t)

	t.Cleanup(func() {
		commands := []TestStep{
			DeleteTestNamespaceCommand(ns),
		}
		RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	cmd := fmt.Sprintf("$KUBECTL_GADGET run %s/trace_oomkill:%s -n %s -o json", *gadgetRepository, *gadgetTag, ns)

	runTraceOOMKill(t, ns, cmd)
}
