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
	"testing"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/file/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestTopFile(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-top-file")

	topFileCmd := &Command{
		Name:         "TopFile",
		Cmd:          fmt.Sprintf("local-gadget top file -o json -m 999 --runtimes=%s", *containerRuntime),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &types.Stats{
				CommonData: eventtypes.CommonData{
					Namespace: ns,
					Pod:       "test-pod",
				},
				// echo is built-in
				Comm:     "sh",
				Filename: "bar",
				FileType: 'R',
			}

			normalize := func(e *types.Stats) {
				e.Container = ""
				e.Pid = 0
				e.Tid = 0
				e.MountNsID = 0
				e.Reads = 0
				e.ReadBytes = 0
				e.Writes = 0
				e.WriteBytes = 0
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		topFileCmd,
		SleepForSecondsCommand(2), // wait to ensure local-gadget has started
		BusyboxPodRepeatCommand(ns, "echo foo > bar"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}
