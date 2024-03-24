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

func runTraceSni(t *testing.T, ns string, cmd string) {
	// TODO: Handle it once we support getting container image name from docker
	isDockerRuntime := IsDockerRuntime(t)

	traceSniCmd := &Command{
		Name:         "StartRunTraceSniGadget",
		Cmd:          cmd,
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedBaseJsonObj := RunEventToObj(t, &types.Event{
				CommonData: BuildCommonDataK8s(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)),
			})

			expectedTraceSniJsonObj := map[string]interface{}{
				"task":      "wget",
				"name":      "inspektor-gadget.io",
				"timestamp": "",
				"pid":       0,
				"tid":       0,
				"uid":       1000,
				"gid":       1111,
				"mntns_id":  0,
				"netns":     0,
			}

			expectedJsonObj := MergeJsonObjs(t, expectedBaseJsonObj, expectedTraceSniJsonObj)

			normalize := func(m map[string]interface{}) {
				SetEventK8sNode(m, "")

				// TODO: Verify container runtime and container name
				SetEventRuntimeName(m, "")
				SetEventRuntimeContainerID(m, "")
				SetEventRuntimeContainerName(m, "")

				m["timestamp"] = ""
				m["pid"] = uint32(0)
				m["tid"] = uint32(0)

				m["mntns_id"] = 0
				m["netns"] = 0
			}

			ExpectEntriesToMatchObj(t, output, normalize, expectedJsonObj)
		},
	}

	commands := []TestStep{
		traceSniCmd,
		BusyboxPodRepeatCommand(ns, "setuidgid 1000:1111 wget --no-check-certificate -T 2 -q -O /dev/null https://inspektor-gadget.io"),
		WaitUntilTestPodReadyCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}

func TestRunTraceSni(t *testing.T) {
	ns := GenerateTestNamespaceName("test-run-trace-sni")

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

	cmd := fmt.Sprintf("$KUBECTL_GADGET run %s/trace_sni:%s -n %s -o json", *gadgetRepository, *gadgetTag, ns)

	runTraceSni(t, ns, cmd)
}
