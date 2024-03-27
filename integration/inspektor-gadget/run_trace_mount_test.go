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

	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func runTraceMount(t *testing.T, ns string, cmd string) {
	// TODO: Handle it once we support getting container image name from docker
	isDockerRuntime := IsDockerRuntime(t)

	traceMountCmd := &Command{
		Name:         "StartRunTraceMountGadget",
		Cmd:          cmd,
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedBaseJsonObj := RunEventToObj(t, &types.Event{
				CommonData: BuildCommonDataK8s(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)),
			})

			expectedTraceMountJsonObj := map[string]interface{}{
				"timestamp":   "",
				"delta":       "",
				"pid":         0,
				"tid":         0,
				"mount_ns_id": 0,
				"ret":         -2,
				"comm":        "mount",
				"fs":          "",
				"src":         "/foo",
				"dest":        "/bar",
				"data":        "",
				"op_str":      "MOUNT",
				// Needed due to op being an enum.
				"op":    0,
				"flags": unix.MS_SILENT,
			}

			expectedJsonObj := MergeJsonObjs(t, expectedBaseJsonObj, expectedTraceMountJsonObj)

			normalize := func(m map[string]interface{}) {
				SetEventK8sNode(m, "")

				// TODO: Verify container runtime and container name
				SetEventRuntimeName(m, "")
				SetEventRuntimeContainerID(m, "")
				SetEventRuntimeContainerName(m, "")

				m["timestamp"] = ""
				m["delta"] = ""
				m["pid"] = uint32(0)
				m["tid"] = uint32(0)
				m["mount_ns_id"] = 0
				m["fs"] = ""
				m["data"] = ""
			}

			ExpectEntriesToMatchObj(t, output, normalize, expectedJsonObj)
		},
	}

	commands := []TestStep{
		traceMountCmd,
		BusyboxPodRepeatCommand(ns, "mount /foo /bar"),
		WaitUntilTestPodReadyCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}

func TestRunTraceMount(t *testing.T) {
	ns := GenerateTestNamespaceName("test-run-trace-mount")

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

	cmd := fmt.Sprintf("$KUBECTL_GADGET run %s/trace_mount:%s -n %s -o json", *gadgetRepository, *gadgetTag, ns)

	runTraceMount(t, ns, cmd)
}
