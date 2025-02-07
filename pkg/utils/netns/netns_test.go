// Copyright 2025 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetFromPidWithAltProcfs(t *testing.T) {
	tests := []struct {
		name          string
		pid           int
		procfs        string
		expectSuccess bool
	}{
		{
			name:          "getting network namespace from pid with alt procfs",
			pid:           1,
			procfs:        "/proc",
			expectSuccess: true,
		},
		{
			name:          `getting network namespace from pid with alt procfs`,
			pid:           1,
			procfs:        "/procfs",
			expectSuccess: true,
		},
		{
			name:          "error",
			pid:           2,
			procfs:        "/procdf",
			expectSuccess: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ns, err := GetFromPidWithAltProcfs(test.pid, test.procfs)
			if test.expectSuccess {
				assert.GreaterOrEqual(t, int(ns), 0)
				assert.NoError(t, err)
			} else {
				assert.Less(t, int(ns), 0)
				assert.Error(t, err)
			}
		})
	}
}

func TestGetFromThreadWithAltProcfs(t *testing.T) {
	tests := []struct {
		name          string
		pid           int
		tid           int
		procfs        string
		expectSuccess bool
	}{
		{
			name:          "getting network namespace from thread with alt procfs",
			pid:           1,
			tid:           1,
			procfs:        "/proc",
			expectSuccess: true,
		},
		{
			name:          `getting network namespace from thread with alt procfs`,
			pid:           1,
			tid:           1,
			procfs:        "/procfs",
			expectSuccess: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ns, err := GetFromThreadWithAltProcfs(test.pid, test.tid, test.procfs)
			if test.expectSuccess {
				assert.GreaterOrEqual(t, int(ns), 0)
				assert.NoError(t, err)
			} else {
				assert.Less(t, int(ns), 0, "Expected an invalid namespace handle")
				assert.Error(t, err)
			}
		})
	}
}
