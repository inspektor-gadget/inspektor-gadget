// Copyright 2019-2024 The Inspektor Gadget authors
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

package tests

import (
	"testing"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type traceOpenEvent struct {
	eventtypes.CommonData

	MountNsID uint64 `json:"mountnsid"`
	Pid       uint32 `json:"pid"`
	Uid       uint32 `json:"uid"`
	Gid       uint32 `json:"gid"`
	Comm      string `json:"comm"`
	Fd        uint32 `json:"fd"`
	Err       int32  `json:"err"`
	Ret       int    `json:"ret"`
	Flags     int    `json:"flags"`
	Mode      int    `json:"mode"`
	FName     string `json:"fname"`
}

func TestTraceOpen(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)

	cn := "test-trace-open"
	containerFactory, err := containers.NewContainerFactory("docker")
	require.NoError(t, err, "new container factory")

	testContainer := containerFactory.NewContainer(
		cn,
		"while true; do setuidgid 1000:1111 cat /dev/null; sleep 0.1; done",
	)
	testContainer.Start(t)
	t.Cleanup(func() {
		testContainer.Stop(t)
	})

	traceOpenCmd := igrunner.New(
		"trace_open",
		igrunner.WithFlags("--runtimes=docker", "--timeout=5"),
		igrunner.WithValidateOutput(
			func(t *testing.T, output string) {
				expectedEntry := &traceOpenEvent{
					CommonData: eventtypes.CommonData{
						Runtime: eventtypes.BasicRuntimeMetadata{
							RuntimeName:   eventtypes.String2RuntimeName("docker"),
							ContainerID:   testContainer.ID(),
							ContainerName: cn,
						},
					},
					Comm:  "cat",
					Fd:    3,
					Err:   0,
					FName: "/dev/null",
					Uid:   1000,
					Gid:   1111,
					Flags: 0,
					Mode:  0,
				}

				normalize := func(e *traceOpenEvent) {
					e.MountNsID = 0
					e.Pid = 0

					e.Runtime.ContainerImageName = ""
					e.Runtime.ContainerImageDigest = ""
				}

				match.ExpectEntriesToMatch(t, output, normalize, expectedEntry)
			}),
	)

	igtesting.RunTestSteps([]igtesting.TestStep{traceOpenCmd}, t)
}
