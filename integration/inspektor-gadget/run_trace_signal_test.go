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

func runTraceSignal(t *testing.T, ns string, cmd string) {
	// TODO: Handle it once we support getting container image name from docker
	isDockerRuntime := IsDockerRuntime(t)

	traceSignalCmd := &Command{
		Name:         "StartRunTraceSignalGadget",
		Cmd:          cmd,
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedBaseJsonObj := RunEventToObj(t, &types.Event{
				CommonData: BuildCommonDataK8s(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)),
			})

			expectedTraceSignalJsonObj := map[string]interface{}{
				"comm":      "sh",
				"sig":       15,
				"ret":       0,
				"uid":       0,
				"gid":       0,
				"pid":       0,
				"tpid":      0,
				"mntns_id":  0,
				"timestamp": "",
			}

			expectedJsonObj := MergeJsonObjs(t, expectedBaseJsonObj, expectedTraceSignalJsonObj)

			normalize := func(m map[string]interface{}) {
				SetEventK8sNode(m, "")

				// TODO: Verify container runtime and container name
				SetEventRuntimeName(m, "")
				SetEventRuntimeContainerID(m, "")
				SetEventRuntimeContainerName(m, "")

				m["timestamp"] = ""
				m["mntns_id"] = 0
				m["pid"] = uint32(0)
				m["tpid"] = 0
			}

			ExpectEntriesToMatchObj(t, output, normalize, expectedJsonObj)
		},
	}

	commands := []TestStep{
		traceSignalCmd,
		BusyboxPodRepeatCommand(ns, "sleep 3 & kill $!"),
		WaitUntilTestPodReadyCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}

func TestRunTraceSignal(t *testing.T) {
	ns := GenerateTestNamespaceName("test-run-trace-signal")

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

	cmd := fmt.Sprintf("$KUBECTL_GADGET run %s/trace_signal:%s -n %s -o json", *gadgetRepository, *gadgetTag, ns)

	runTraceSignal(t, ns, cmd)
}
