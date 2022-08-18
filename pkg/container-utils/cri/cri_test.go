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
	"testing"

	runtimeclient "github.com/kinvolk/inspektor-gadget/pkg/container-utils/runtime-client"
)

func TestParseExtraInfo(t *testing.T) {
	type Mount struct {
		src string
		dst string
	}
	type Expected struct {
		pid         *int
		cgroupsPath *string
		mounts      *[]Mount
	}
	table := []struct {
		description string
		info        map[string]string
		expected    *Expected
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
			expected:    &Expected{pid: expect(1234)},
		},
		{
			description: "Former format: cgroupPath missing",
			info: map[string]string{
				"sandboxID": "myID", "pid": "1234",
				"runtimeSpec": "{\"linux\":{\"cgroupsPath2\":\"/mypath\"}}",
			},
			expected: &Expected{pid: expect(1234)},
		},
		{
			description: "Former format: cgroupPath",
			info: map[string]string{
				"sandboxID": "myID", "pid": "1234",
				"runtimeSpec": "{\"linux\":{\"cgroupsPath\":\"/mypath\"}}",
			},
			expected: &Expected{pid: expect(1234), cgroupsPath: expect("/mypath")},
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
			expected: &Expected{
				pid: expect(1234), cgroupsPath: expect("/mypath"),
				mounts: expect([]Mount{
					{src: "/src/a1", dst: "/dst/b1"},
					{src: "/src/a2", dst: "/dst/b2"},
				}),
			},
		},
		// New format
		{
			description: "New format: Invalid format",
			info:        map[string]string{"info": "{\"InvalidFormat\"}"},
		},
		{
			description: "New format: No pid entry",
			info:        map[string]string{"info": "{\"sandboxID\":\"myID\"}"},
		},
		{
			description: "New format: Zero pid",
			info:        map[string]string{"info": "{\"sandboxID\":\"myID\",\"pid\":0"},
		},
		{
			description: "New format: Invalid PID",
			info:        map[string]string{"info": "{\"sandboxID\":\"myID\",\"pid\":1.2"},
		},
		{
			description: "New format: Pid 1234",
			info:        map[string]string{"info": "{\"sandboxID\":\"myID\",\"pid\":1234}"},
			expected:    &Expected{pid: expect(1234)},
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
			expected: &Expected{pid: expect(1234)},
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
			expected: &Expected{pid: expect(1234), cgroupsPath: expect("/mypath")},
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
			expected: &Expected{
				pid: expect(1234), cgroupsPath: expect("/mypath"),
				mounts: expect([]Mount{
					{src: "/src/a1", dst: "/dst/b1"},
					{src: "/src/a2", dst: "/dst/b2"},
				}),
			},
		},
	}

	// Iterate on all tests.
	for _, entry := range table {
		// Parse the extra info.
		var containerExtendedData runtimeclient.ContainerExtendedData
		err := parseExtraInfo(entry.info, &containerExtendedData)
		// Expected error.
		if err != nil {
			if entry.expected != nil {
				t.Fatalf("Failed test %q: unexpected error: %s", entry.description, err.Error())
			}
			if containerExtendedData.Pid != -1 {
				t.Fatalf("Failed test %q: PID %d when expected -1", entry.description, containerExtendedData.Pid)
			}

			// An error was returned, no point in checking rest of fields.
			continue
		}

		// Make sure expected field was filled.
		if entry.expected == nil {
			t.Fatalf("Failed test %q: unexpected success (expected error)", entry.description)
		}

		// PID
		if entry.expected.pid != nil && containerExtendedData.Pid != *entry.expected.pid {
			t.Fatalf("Failed test %q: PID %d when expected %d", entry.description,
				containerExtendedData.Pid, *entry.expected.pid)
		}

		// CgroupsPath
		if entry.expected.cgroupsPath != nil {
			if containerExtendedData.CgroupsPath != *entry.expected.cgroupsPath {
				t.Fatalf("Failed test %q: cgroupPath \"%s\" when expected \"%s\"", entry.description,
					containerExtendedData.CgroupsPath, *entry.expected.cgroupsPath)
			}
		} else {
			if containerExtendedData.CgroupsPath != "" {
				t.Fatalf("Failed test %q: cgroupPath \"%s\" when expected \"\"", entry.description,
					containerExtendedData.CgroupsPath)
			}
		}

		// Mounts
		if entry.expected.mounts != nil {
			if len(containerExtendedData.Mounts) != len(*entry.expected.mounts) {
				t.Fatalf("Failed test %q: mounts number of elements %d when expected %d", entry.description,
					len(containerExtendedData.Mounts), len(*entry.expected.mounts))
			}

			for i := range *entry.expected.mounts {
				if containerExtendedData.Mounts[i].Source != (*entry.expected.mounts)[i].src {
					t.Fatalf("Failed test %q: mounts[%d] source \"%s\" when expected \"%s\"", entry.description,
						i, containerExtendedData.Mounts[i].Source, (*entry.expected.mounts)[i].src)
				}
				if containerExtendedData.Mounts[i].Destination != (*entry.expected.mounts)[i].dst {
					t.Fatalf("Failed test %q: mounts[%d] destination \"%s\" when expected \"%s\"", entry.description,
						i, containerExtendedData.Mounts[i].Destination, (*entry.expected.mounts)[i].dst)
				}
			}
		} else {
			if len(containerExtendedData.Mounts) != 0 {
				t.Fatalf("Failed test %q: mounts number of elements %d when expected 0", entry.description,
					len(containerExtendedData.Mounts))
			}
		}
	}
}

func expect[T any](v T) *T {
	return &v
}
