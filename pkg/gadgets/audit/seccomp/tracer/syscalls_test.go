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

package tracer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSyscallToName(t *testing.T) {
	tests := []struct {
		name    string
		syscall int
		want    string
	}{
		{
			name:    "syscall 0",
			syscall: 0,
			want:    "read",
		},
		{
			name:    "syscall 436",
			syscall: 436,
			want:    "close_range",
		},
		{
			name:    "syscall -1",
			syscall: -1,
			want:    "syscall-1",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := syscallToName(test.syscall)
			assert.Equal(t, test.want, res)
		})
	}
}

func TestCodeToName(t *testing.T) {
	tests := []struct {
		name string
		code uint
		want string
	}{
		{
			name: "kill process",
			code: SECCOMP_RET_KILL_PROCESS,
			want: "kill_process",
		},
		{
			name: "kill thread",
			code: SECCOMP_RET_KILL_THREAD,
			want: "kill_thread",
		},
		{
			name: "kill thread",
			code: SECCOMP_RET_TRAP,
			want: "trap",
		},
		{
			name: "errno",
			code: SECCOMP_RET_ERRNO,
			want: "errno",
		},
		{
			name: "user_notif",
			code: SECCOMP_RET_USER_NOTIF,
			want: "user_notif",
		},
		{
			name: "trace",
			code: SECCOMP_RET_TRACE,
			want: "trace",
		},
		{
			name: "log",
			code: SECCOMP_RET_LOG,
			want: "log",
		},
		{
			name: "allow",
			code: SECCOMP_RET_ALLOW,
			want: "allow",
		},
		{
			name: "unknown",
			code: 3546434,
			want: "unknown",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := codeToName(test.code)
			assert.Equal(t, test.want, res)
		})
	}
}
