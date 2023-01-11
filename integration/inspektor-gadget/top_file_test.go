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

	topfileTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/file/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestTopFile(t *testing.T) {
	ns := GenerateTestNamespaceName("test-top-file")

	t.Parallel()

	topFileCmd := &Command{
		Name:         "StartFiletopGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET top file -n %s --sort \"-writes\" -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &topfileTypes.Stats{
				CommonData: BuildCommonData(ns),
				Reads:      0,
				ReadBytes:  0,
				Filename:   "date.txt",
				FileType:   byte('R'), // Regular file
				Comm:       "sh",
			}

			normalize := func(e *topfileTypes.Stats) {
				e.Node = ""
				e.Writes = 0
				e.WriteBytes = 0
				e.Pid = 0
				e.Tid = 0
				e.MountNsID = 0
			}

			return ExpectEntriesInMultipleArrayToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		topFileCmd,
		BusyboxPodRepeatCommand(ns, "echo date >> /tmp/date.txt"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}
