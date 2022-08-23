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

package cri

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	runtimeclient "github.com/kinvolk/inspektor-gadget/pkg/container-utils/runtime-client"
)

func TestParseExtraInfo(t *testing.T) {
	table := []struct {
		description string
		info        map[string]string
		expected    *runtimeclient.ContainerExtraInfo
	}{
		// Invalid params
		{
			description: "From empty map",
			info:        map[string]string{},
		},
		{
			description: "Nil map",
			info:        nil,
		},
		// Former format
		{
			description: "Former format: No pid entry",
			info:        map[string]string{"sandboxID": "myID"},
		},
		{
			description: "Former format: Invalid PID",
			info:        map[string]string{"sandboxID": "myID", "pid": "abc"},
		},
		{
			description: "Former format: Zero PID",
			info:        map[string]string{"sandboxID": "myID", "pid": "0"},
		},
		{
			description: "Former format: Pid 1234",
			info:        map[string]string{"sandboxID": "myID", "pid": "1234"},
			expected:    &runtimeclient.ContainerExtraInfo{Pid: 1234},
		},
		{
			description: "Former format: cgroupPath missing",
			info: map[string]string{
				"sandboxID": "myID", "pid": "1234",
				"runtimeSpec": `{"linux":{"cgroupsPath2":"/mypath"}}`,
			},
			expected: &runtimeclient.ContainerExtraInfo{Pid: 1234},
		},
		{
			description: "Former format: cgroupPath",
			info: map[string]string{
				"sandboxID": "myID", "pid": "1234",
				"runtimeSpec": `{"linux":{"cgroupsPath":"/mypath"}}`,
			},
			expected: &runtimeclient.ContainerExtraInfo{Pid: 1234, CgroupsPath: "/mypath"},
		},
		{
			description: "Former format: mounts",
			info: map[string]string{
				"sandboxID": "myID", "pid": "1234",
				"runtimeSpec": `{
					"linux": { "cgroupsPath": "/mypath" },
					"mounts": [
						{
							"source": "/src/a1",
							"destination": "/dst/b1"
						},
						{
							"source": "/src/a2",
							"destination": "/dst/b2"
						}
					]
				}`,
			},
			expected: &runtimeclient.ContainerExtraInfo{
				Pid:         1234,
				CgroupsPath: "/mypath",
				Mounts: []runtimeclient.ContainerMountData{
					{Source: "/src/a1", Destination: "/dst/b1"},
					{Source: "/src/a2", Destination: "/dst/b2"},
				},
			},
		},
		// New format
		{
			description: "New format: Invalid format",
			info:        map[string]string{"info": `{"InvalidFormat"}`},
		},
		{
			description: "New format: No pid entry",
			info:        map[string]string{"info": `{"sandboxID":"myID"}`},
		},
		{
			description: "New format: Zero pid",
			info:        map[string]string{"info": `{"sandboxID":"myID","pid":0}`},
		},
		{
			description: "New format: Invalid PID",
			info:        map[string]string{"info": `{"sandboxID":"myID","pid":1.2}`},
		},
		{
			description: "New format: Pid 1234",
			info:        map[string]string{"info": `{"sandboxID":"myID","pid":1234}`},
			expected:    &runtimeclient.ContainerExtraInfo{Pid: 1234},
		},

		{
			description: "New format: cgroupPath missing",
			info: map[string]string{
				"info": `{
					"pid": 1234,
					"runtimeSpec": {
						"linux": { "cgroupsPath2": "/mypath" }
					}
				}`,
			},
			expected: &runtimeclient.ContainerExtraInfo{Pid: 1234},
		},
		{
			description: "New format: cgroupPath",
			info: map[string]string{
				"info": `{
					"pid": 1234,
					"runtimeSpec": {
						"linux": { "cgroupsPath": "/mypath" }
					}
				}`,
			},
			expected: &runtimeclient.ContainerExtraInfo{Pid: 1234, CgroupsPath: "/mypath"},
		},
		{
			description: "New format: mounts",
			info: map[string]string{
				"info": `{
					"pid": 1234,
					"runtimeSpec": {
						"linux": { "cgroupsPath": "/mypath" },
						"mounts": [
							{
								"source": "/src/a1",
								"destination": "/dst/b1"
							},
							{
								"source": "/src/a2",
								"destination": "/dst/b2"
							}
						]
					}
				}`,
			},
			expected: &runtimeclient.ContainerExtraInfo{
				Pid:         1234,
				CgroupsPath: "/mypath",
				Mounts: []runtimeclient.ContainerMountData{
					{Source: "/src/a1", Destination: "/dst/b1"},
					{Source: "/src/a2", Destination: "/dst/b2"},
				},
			},
		},
	}

	// Iterate on all tests.
	for _, entry := range table {
		// Parse the extra info.
		extraInfo, err := parseExtraInfo(entry.info)
		// Expected error.
		if err != nil {
			if entry.expected != nil {
				t.Fatalf("Failed test %q: unexpected error: %s", entry.description, err.Error())
			}
			if extraInfo != nil {
				t.Fatalf("Failed test %q: extra info exists", entry.description)
			}

			// An error was returned, no point in checking rest of fields.
			continue
		}

		// Make sure expected field was filled.
		if entry.expected == nil {
			t.Fatalf("Failed test %q: unexpected success (expected error)", entry.description)
		}
		if extraInfo == nil {
			t.Fatalf("Failed test %q: extra info is missing", entry.description)
		}

		if !reflect.DeepEqual(entry.expected, extraInfo) {
			t.Fatalf("%q: event doesn't match:\n%s", entry.description,
				cmp.Diff(entry.expected, extraInfo))
		}
	}
}
