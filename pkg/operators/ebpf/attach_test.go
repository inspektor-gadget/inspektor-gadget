// Copyright 2026 The Inspektor Gadget authors
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

package ebpfoperator

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSplitTracepoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		attachTo  string
		wantGroup string
		wantName  string
		wantErr   bool
	}{
		{attachTo: "syscalls/sys_enter_openat", wantGroup: "syscalls", wantName: "sys_enter_openat"},
		{attachTo: "", wantErr: true},
		{attachTo: "sys_enter_openat", wantErr: true},
		{attachTo: "syscalls/", wantErr: true},
		{attachTo: "/sys_enter_openat", wantErr: true},
		{attachTo: "/", wantErr: true},
		{attachTo: "syscalls/sys_enter_openat/extra", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.attachTo, func(t *testing.T) {
			t.Parallel()

			group, name, err := splitTracepoint(tt.attachTo)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantGroup, group)
			require.Equal(t, tt.wantName, name)
		})
	}
}
