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

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	snapshotprocessTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/process/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestSnapshotProcess(t *testing.T) {
	t.Parallel()
	cn := "test-snapshot-process"

	snapshotProcessCmd := &Command{
		Name: "SnapshotProcess",
		Cmd:  fmt.Sprintf("./ig snapshot process -o json --runtimes=%s -c %s", *runtime, cn),
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &snapshotprocessTypes.Event{
				Event: eventtypes.Event{
					Type: eventtypes.NORMAL,
					CommonData: eventtypes.CommonData{
						K8s: eventtypes.K8sMetadata{
							BasicK8sMetadata: eventtypes.BasicK8sMetadata{
								ContainerName: cn,
							},
						},
					},
				},
				Command: "nc",
			}

			normalize := func(e *snapshotprocessTypes.Event) {
				e.Pid = 0
				e.Tid = 0
				e.ParentPid = 0
				e.MountNsID = 0
			}

			return ExpectEntriesInArrayToMatch(output, normalize, expectedEntry)
		},
	}

	testSteps := []TestStep{
		containerFactory.NewContainer(ContainerSpec{
			Name:         cn,
			Cmd:          "nc -l -p 9090",
			StartAndStop: true,
		}),
		snapshotProcessCmd,
	}

	RunTestSteps(testSteps, t)
}
