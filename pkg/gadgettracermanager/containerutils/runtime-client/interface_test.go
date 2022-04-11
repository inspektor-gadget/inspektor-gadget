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

package runtimeclient

import (
	"testing"
)

func TestParseExtraInfo(t *testing.T) {
	table := []struct {
		description string
		info        map[string]string
		expectedPid int
	}{
		// Invalid params
		{
			description: "From empty map",
			info:        map[string]string{},
			expectedPid: -1,
		},
		{
			description: "Nil map",
			info:        nil,
			expectedPid: -1,
		},
		// Former format
		{
			description: "Former format: No pid entry",
			info:        map[string]string{"sandboxID": "myID"},
			expectedPid: -1,
		},
		{
			description: "Former format: Invalid PID",
			info:        map[string]string{"sandboxID": "myID", "pid": "abc"},
			expectedPid: -1,
		},
		{
			description: "Former format: Pid 1234",
			info:        map[string]string{"sandboxID": "myID", "pid": "1234"},
			expectedPid: 1234,
		},
		// New format
		{
			description: "New format: Invalid format",
			info:        map[string]string{"info": "{\"InvalidFormat\"}"},
			expectedPid: -1,
		},
		{
			description: "New format: No pid entry",
			info:        map[string]string{"info": "{\"sandboxID\":\"myID\"}"},
			expectedPid: 0,
		},
		{
			description: "New format: Invalid PID",
			info:        map[string]string{"info": "{\"sandboxID\":\"myID\",\"pid\":1.2"},
			expectedPid: -1,
		},
		{
			description: "New format: Pid 1234",
			info:        map[string]string{"info": "{\"sandboxID\":\"myID\",\"pid\":1234}"},
			expectedPid: 1234,
		},
	}

	for _, entry := range table {
		pid, err := parseExtraInfo(entry.info)
		if entry.expectedPid != pid || (pid == -1 && err == nil) || (pid != -1 && err != nil) {
			t.Fatalf("Failed test %q: result %d (err %s) vs expected %d",
				entry.description, pid, err, entry.expectedPid)
		}
	}
}
