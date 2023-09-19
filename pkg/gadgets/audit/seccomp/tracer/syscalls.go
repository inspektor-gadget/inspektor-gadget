//go:build !docs
// +build !docs

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

package tracer

import (
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/syscalls"
)

const (
	SECCOMP_RET_KILL_PROCESS = 0x80000000
	SECCOMP_RET_KILL_THREAD  = 0x00000000
	SECCOMP_RET_KILL         = SECCOMP_RET_KILL_THREAD
	SECCOMP_RET_TRAP         = 0x00030000
	SECCOMP_RET_ERRNO        = 0x00050000
	SECCOMP_RET_USER_NOTIF   = 0x7fc00000
	SECCOMP_RET_TRACE        = 0x7ff00000
	SECCOMP_RET_LOG          = 0x7ffc0000
	SECCOMP_RET_ALLOW        = 0x7fff0000
	SECCOMP_RET_ACTION_FULL  = 0xffff0000
)

func syscallToName(syscall int) string {
	name, ok := syscalls.GetSyscallNameByNumber(syscall)
	if !ok {
		name = fmt.Sprintf("syscall%d", syscall)
	}
	return name
}

func codeToName(code uint) string {
	switch code & SECCOMP_RET_ACTION_FULL {
	case SECCOMP_RET_KILL_PROCESS:
		return "kill_process"
	case SECCOMP_RET_KILL_THREAD:
		return "kill_thread"
	case SECCOMP_RET_TRAP:
		return "trap"
	case SECCOMP_RET_ERRNO:
		return "errno"
	case SECCOMP_RET_USER_NOTIF:
		return "user_notif"
	case SECCOMP_RET_TRACE:
		return "trace"
	case SECCOMP_RET_LOG:
		return "log"
	case SECCOMP_RET_ALLOW:
		return "allow"
	default:
		return "unknown"
	}
}
