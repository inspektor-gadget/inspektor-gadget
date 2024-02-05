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

package common

import (
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/integration"
	cpuprofileTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/cpu/types"
)

func NewProfileCPUTestCmds(cmd string, ns string, normalize func(e *cpuprofileTypes.Report), commonDataOpts ...integration.CommonDataOption) []*integration.Command {
	profileCPUCmd := &integration.Command{
		Name: "ProfileCpu",
		Cmd:  cmd,
		ValidateOutput: func(t *testing.T, output string) {
			expectedEntry := &cpuprofileTypes.Report{
				CommonData: integration.BuildCommonData(ns,
					commonDataOpts...,
				),
				Comm: "sh",
			}

			integration.ExpectEntriesToMatch(t, output, normalize, expectedEntry)
		},
	}

	commands := []*integration.Command{
		integration.CreateTestNamespaceCommand(ns),
		integration.BusyboxPodCommand(ns, "while true; do echo foo > /dev/null; done"),
		integration.WaitUntilTestPodReadyCommand(ns),
		profileCPUCmd,
		integration.DeleteTestNamespaceCommand(ns),
	}

	return commands
}

func ProfileCPUNormalize(opts ...func(e *cpuprofileTypes.Report)) func(e *cpuprofileTypes.Report) {
	return func(e *cpuprofileTypes.Report) {
		e.Pid = 0
		e.UserStack = nil
		e.KernelStack = nil
		e.Count = 0
		e.Runtime.ContainerID = ""
		e.Runtime.ContainerImageDigest = ""

		for _, option := range opts {
			option(e)
		}
	}
}
