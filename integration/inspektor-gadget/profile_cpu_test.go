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

	profilecpuTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/cpu/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestProfileCpu(t *testing.T) {
	ns := GenerateTestNamespaceName("test-profile-cpu")

	t.Parallel()

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		BusyboxPodCommand(ns, "while true; do echo foo > /dev/null; done"),
		WaitUntilTestPodReadyCommand(ns),
		{
			Name: "RunProfileCpuGadget",
			Cmd:  fmt.Sprintf("$KUBECTL_GADGET profile cpu -n %s -p test-pod -K --timeout 15 -o json", ns),
			ExpectedOutputFn: func(output string) error {
				expectedEntry := &profilecpuTypes.Report{
					CommonData: BuildCommonData(ns),
					Comm:       "sh",
				}

				normalize := func(e *profilecpuTypes.Report) {
					e.Pid = 0
					e.UserStack = nil
					e.KernelStack = nil
					e.Count = 0

					e.K8s.Node = ""
					// TODO: Verify container runtime and container name
					e.Runtime = types.BasicRuntimeMetadata{}
				}

				return ExpectEntriesToMatch(output, normalize, expectedEntry)
			},
		},
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
