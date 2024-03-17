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

	"github.com/inspektor-gadget/inspektor-gadget/integration"
	IG "github.com/inspektor-gadget/inspektor-gadget/pkg/test-fw/ig"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type EventType string

const ImageName = "docker.io/pawarpranav83/trace_open:latest"

type Event struct {
	eventtypes.CommonData

	// Type indicates the kind of this event
	Type EventType `json:"type"`

	// Message when Type is ERR, WARN, DEBUG or INFO
	Message string `json:"message,omitempty"`
}

// A user would have to implement their own event type as well, therefore not using this from ig repo
type traceOpenEvent struct {
	Event
	eventtypes.WithMountNsID

	Pid      uint32      `json:"pid,omitempty" column:"pid,minWidth:7"`
	Uid      uint32      `json:"uid,omitempty" column:"uid,minWidth:10,hide"`
	Gid      uint32      `json:"gid" column:"gid,template:gid,hide"`
	Comm     string      `json:"comm,omitempty" column:"comm,maxWidth:16"`
	Ret      int         `json:"ret,omitempty" column:"ret,width:3,fixed,hide"`
	Err      int         `json:"err,omitempty" column:"err,width:3,fixed"`
	Flags    int         `json:"flags,omitempty" column:"flags,width:24,hide"`
	FlagsRaw int32       `json:"flagsRaw,omitempty"`
	Mode     int         `json:"mode,omitempty" column:"mode,width:10,hide"`
	ModeRaw  fs.FileMode `json:"modeRaw,omitempty"`
	FName    string      `json:"fname,omitempty" column:"path,minWidth:24,width:32"`
	FullPath string      `json:"fullPath,omitempty" column:"fullPath,minWidth:24,width:32" columnTags:"param:full-path"`
}

func TestTraceOpen(t *testing.T) {
	cn := "test-trace-open"
	containerFactory, err := integration.NewContainerFactory("docker")
	if err != nil {
		t.Logf(err.Error())
		return
	}

	ig, err := IG.New(
		IG.WithPath("ig"),
		IG.WithImage("ghcr.io/inspektor-gadget/gadget/trace_open:latest"),
		IG.WithFlags("--runtimes=docker", "-o=json"),
		IG.WithStartAndStop(),
	)
	if err != nil {
		t.Logf(err.Error())
		return
	}

	traceOpenCmd := &IG.Command{
		IG:   *ig,
		Name: "TraceOpen",
		ValidateOutput: func(t *testing.T, output string) {
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

			IG.ExpectEntriesToMatch(t, output, normalize, expectedEntry)

		},
	}
	testSteps := []IG.TestStep{
		traceOpenCmd,
		containerFactory.NewContainer(cn, "setuidgid 1000:1111 cat /dev/null"),
	}

	IG.RunTestSteps(testSteps, t)
}
