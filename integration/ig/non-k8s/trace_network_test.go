// Copyright 2022-2024 The Inspektor Gadget authors
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
	networkTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestTraceNetwork(t *testing.T) {
	t.Parallel()
	cn := "test-trace-network"

	traceNetworkCmd := &Command{
		Name:         "TraceNetwork",
		Cmd:          fmt.Sprintf("./ig trace network -o json --runtimes=%s -c %s", *runtime, cn),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedEntries := []*networkTypes.Event{
				{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
						CommonData: eventtypes.CommonData{
							Runtime: eventtypes.BasicRuntimeMetadata{
								RuntimeName:   eventtypes.String2RuntimeName(*runtime),
								ContainerName: cn,
							},
						},
					},
					Comm:    "curl",
					Uid:     0,
					Gid:     0,
					PktType: "OUTGOING",
					Proto:   "TCP",
					Port:    80,
					DstEndpoint: eventtypes.L3Endpoint{
						Addr:    "127.0.0.1",
						Version: 4,
					},
				},
				{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
						CommonData: eventtypes.CommonData{
							Runtime: eventtypes.BasicRuntimeMetadata{
								RuntimeName:   eventtypes.String2RuntimeName(*runtime),
								ContainerName: cn,
							},
						},
					},
					Comm:    "nginx",
					PktType: "HOST",
					Proto:   "TCP",
					Port:    80,
					DstEndpoint: eventtypes.L3Endpoint{
						Addr:    "127.0.0.1",
						Version: 4,
					},
				},
			}

			normalize := func(e *networkTypes.Event) {
				e.Timestamp = 0
				e.MountNsID = 0
				e.NetNsID = 0
				e.Pid = 0
				e.Tid = 0
				// nginx uses multiple processes, in this case Inspektor Gadget is
				// not able to determine the UID / GID in a reliable way.
				e.Uid = 0
				e.Gid = 0

				e.Runtime.ContainerID = ""
				e.Runtime.ContainerPID = 0
				e.Runtime.ContainerStartedAt = 0
				// TODO: Handle once we support getting ContainerImageName from Docker
				e.Runtime.ContainerImageName = ""
				e.Runtime.ContainerImageDigest = ""
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntries...)
		},
	}

	testSteps := []TestStep{
		traceNetworkCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		containerFactory.NewContainer(cn, "nginx && curl 127.0.0.1", containers.WithContainerImage("ghcr.io/inspektor-gadget/ci/nginx:latest")),
	}

	RunTestSteps(testSteps, t)
}
