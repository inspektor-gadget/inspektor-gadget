// Copyright 2023-2024 The Inspektor Gadget authors
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

func runTraceTcp(t *testing.T, ns string, cmd string) {
	// TODO: Handle it once we support getting container image name from docker
	isDockerRuntime := IsDockerRuntime(t)

	traceTcpCmd := &Command{
		Name:         "StartRunTraceTcpGadget",
		Cmd:          cmd,
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedBaseJsonObj := RunEventToObj(t, &types.Event{
				CommonData: BuildCommonData(ns, WithContainerImageName("docker.io/library/nginx:latest", isDockerRuntime)),
			})

			expectedTraceTcpJsonObj := map[string]interface{}{
				"task":      "curl",
				"timestamp": 0,
				"src":       "",
				"dst":       "",
				"type_str":  "connect",
				// needed due to type being an enum
				"type":     0,
				"pid":      0,
				"uid":      0,
				"gid":      0,
				"mntns_id": 0,
				"netns":    0,
			}

			expectedJsonObj := MergeJsonObjs(t, expectedBaseJsonObj, expectedTraceTcpJsonObj)

			normalize := func(m map[string]interface{}) {
				SetEventK8sNode(m, "")

				// TODO: Verify container runtime and container name
				SetEventRuntimeName(m, "")
				SetEventRuntimeContainerID(m, "")
				SetEventRuntimeContainerName(m, "")

				m["timestamp"] = 0
				m["src"] = ""
				m["dst"] = ""
				m["pid"] = uint32(0)
				m["mntns_id"] = 0
				m["netns"] = 0
			}

			ExpectEntriesToMatchObj(t, output, normalize, expectedJsonObj)
		},
	}

	commands := []TestStep{
		traceTcpCmd,
		// TODO: can't use setuidgid because it's not available on the nginx image
		PodCommand("test-pod", "nginx", ns, "[sh, -c]", "nginx && while true; do curl 127.0.0.1; sleep 0.1; done"),
		WaitUntilTestPodReadyCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}

func TestRunTraceTcp(t *testing.T) {
	ns := GenerateTestNamespaceName("test-run-trace-tcp")

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

	cmd := fmt.Sprintf("$KUBECTL_GADGET run %s/trace_tcp:%s -n %s -o json", *gadgetRepository, *gadgetTag, ns)

	runTraceTcp(t, ns, cmd)
}
