// Copyright 2019-2021 The Inspektor Gadget authors
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
	"io/fs"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/integration"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/command"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Event struct {
	eventtypes.CommonData

	// Type indicates the kind of this event
	Type string `json:"type"`

	// Message when Type is ERR, WARN, DEBUG or INFO
	Message string `json:"message,omitempty"`
}

type traceOpenEvent struct {
	Event

	MountNsID uint64      `json:"mountnsid"`
	Pid       uint32      `json:"pid"`
	Uid       uint32      `json:"uid"`
	Gid       uint32      `json:"gid"`
	Comm      string      `json:"comm"`
	Ret       int         `json:"ret"`
	Err       int         `json:"err"`
	Flags     int         `json:"flags"`
	FlagsRaw  int32       `json:"flagsRaw"`
	Mode      int         `json:"mode"`
	ModeRaw   fs.FileMode `json:"modeRaw"`
	FName     string      `json:"fname"`
	FullPath  string      `json:"fullPath"`
}

func TestTraceOpen(t *testing.T) {
	cn := "test-trace-open"
	containerFactory, err := integration.NewContainerFactory("docker")
	require.NoError(t, err, "new container factory")

	traceOpenCmd := igrunner.New(
		igrunner.WithPath("ig"),
		igrunner.WithImage("ghcr.io/inspektor-gadget/gadget/trace_open:latest"),
		igrunner.WithFlags("--runtimes=docker", "-o=json"),
		igrunner.WithStartAndStop(),
		igrunner.WithValidateOutput(func(t *testing.T, output string) {
			expectedEntry := &traceOpenEvent{
				Event: Event{
					Type: "",
					CommonData: eventtypes.CommonData{
						Runtime: eventtypes.BasicRuntimeMetadata{
							RuntimeName:   eventtypes.String2RuntimeName("docker"),
							ContainerName: cn,
						},
					},
				},
				Comm:     "cat",
				Ret:      3,
				Err:      0,
				FName:    "/dev/null",
				FullPath: "",
				Uid:      1000,
				Gid:      1111,
				Flags:    0,
				Mode:     0,
			}

			normalize := func(e *traceOpenEvent) {
				e.MountNsID = 0
				e.Pid = 0

				e.Runtime.ContainerID = ""
				e.Runtime.ContainerImageName = ""
				e.Runtime.ContainerImageDigest = ""
			}

			match.ExpectEntriesToMatch(t, output, normalize, expectedEntry)
		}),
	)

	testSteps := []command.TestStep{
		traceOpenCmd,
		containerFactory.NewContainer(cn, "setuidgid 1000:1111 cat /dev/null"),
	}

	command.RunTestSteps(testSteps, t)
}
