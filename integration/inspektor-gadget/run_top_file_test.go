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

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func runTopFile(t *testing.T, ns string, cmd string) {
	// TODO: Handle it once we support getting container image name from docker
	isDockerRuntime := IsDockerRuntime(t)

	topFileCmd := &Command{
		Name:         "StartRunTopFileGadget",
		Cmd:          cmd,
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedBaseJsonObj := RunEventToObj(t, &types.Event{
				CommonData: BuildCommonData(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)),
			})

			expectedTopFIleJsonObj := map[string]interface{}{
				"file":   "date.txt",
				"t":      "R", // Regular file
				"comm":   "sh",
				"reads":  0,
				"rbytes": 0,

				// Normalized fields
				"t_raw":    0,
				"pid":      0,
				"tid":      0,
				"writes":   0,
				"wbytes":   0,
				"mntns_id": 0,
			}

			expectedJsonObj := MergeJsonObjs(t, expectedBaseJsonObj, expectedTopFIleJsonObj)

			normalize := func(m map[string]interface{}) {
				SetEventK8sNode(m, "")

				// TODO: Verify container runtime and container name
				SetEventRuntimeName(m, "")
				SetEventRuntimeContainerID(m, "")
				SetEventRuntimeContainerName(m, "")

				m["pid"] = uint32(0)
				m["tid"] = uint32(0)
				m["writes"] = uint64(0)
				m["wbytes"] = uint64(0)
				m["mntns_id"] = 0
				m["t_raw"] = 0
			}

			ExpectEntriesInMultipleArrayToMatchObj(t, output, normalize, expectedJsonObj)
		},
	}

	commands := []TestStep{
		topFileCmd,
		BusyboxPodRepeatCommand(ns, "echo date >> /tmp/date.txt"),
		WaitUntilTestPodReadyCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}

func TestRunTopFile(t *testing.T) {
	t.Skip("not correctly handled by refactoring, yet (missing support for arrays as result)")
	ns := GenerateTestNamespaceName("test-run-top-file")

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

	cmd := fmt.Sprintf("$KUBECTL_GADGET run %s/top_file:%s -n %s -o json", *gadgetRepository, *gadgetTag, ns)

	runTopFile(t, ns, cmd)
}
