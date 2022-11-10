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
	networkTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestTraceNetwork(t *testing.T) {
	t.Parallel()
	cn := "test-trace-dns"

	traceNetworkCmd := &Command{
		Name:         "TraceNetwork",
		Cmd:          fmt.Sprintf("./local-gadget trace network -o json --runtimes=docker -c %s", cn),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntries := []*networkTypes.Event{
				{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
						CommonData: eventtypes.CommonData{
							Namespace: "default",
							Pod:       cn,
							Container: cn,
						},
					},
					PktType:    "OUTGOING",
					Proto:      "tcp",
					Port:       80,
					RemoteAddr: "127.0.0.1",
				},
				{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
						CommonData: eventtypes.CommonData{
							Namespace: "default",
							Pod:       cn,
							Container: cn,
						},
					},
					PktType:    "HOST",
					Proto:      "tcp",
					Port:       80,
					RemoteAddr: "127.0.0.1",
				},
			}

			return ExpectEntriesToMatch(output, nil, expectedEntries...)
		},
	}

	testSteps := []TestStep{
		traceNetworkCmd,
		&DockerContainer{
			Name:    cn,
			Cmd:     "nginx && curl 127.0.0.1",
			Options: NewDockerOptions(WithDockerImage("docker.io/library/nginx")),
		},
	}

	RunTestSteps(testSteps, t)
}
