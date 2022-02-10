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

package crio

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
		// Format < v1.18.0
		{
			description: "Format < v1.18.0: No pid entry",
			info:        map[string]string{"sandboxID": "myID"},
			expectedPid: -1,
		},
		{
			description: "Format < v1.18.0: Invalid PID",
			info:        map[string]string{"sandboxID": "myID", "pid": "abc"},
			expectedPid: -1,
		},
		{
			description: "Format < v1.18.0: Pid 1234",
			info:        map[string]string{"sandboxID": "myID", "pid": "1234"},
			expectedPid: 1234,
		},
		// Format > v1.18.0
		{
			description: "Format > v1.18.0: No pid entry",
			info:        map[string]string{"info": "{\"sandboxID\":\"myID\"}"},
			expectedPid: -1,
		},
		{
			description: "Format > v1.18.0: Invalid PID",
			info:        map[string]string{"info": "{\"sandboxID\":\"myID\",\"pid\":1.2"},
			expectedPid: -1,
		},
		{
			description: "Format > v1.18.0: Pid 1234",
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
