// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 The Inspektor Gadget authors

#ifndef __EXEC_FIXES_H
#define __EXEC_FIXES_H

#include <bpf/bpf_helpers.h>

// This header is used to obtain the correct PID when passing data across
// an execve syscall.
//
// man clone(2):
//   If any of the threads in a thread group performs an
//   execve(2), then all threads other than the thread group
//   leader are terminated, and the new program is executed in
//   the thread group leader.
//
// sys_enter_execve might be called from a thread and the corresponding
// sys_exit_execve will be called from the thread group leader in case of
// execve success, or from the same thread in case of execve failure. So we
// need to lookup the pid from the tgid in sys_exit_execve.
//
// We don't know in advance which execve(2) will succeed, so we need to keep
// track of all tgid<->pid mappings in a BPF map.
//
// We don't want to use bpf_for_each_map_elem() because it requires Linux 5.13.
//
// If several execve(2) are performed in parallel from different threads, only
// one can succeed. The kernel will run the tracepoint syscalls/sys_exit_execve
// for the failing execve(2) first and then for the successful one last.
//
// So we can insert a tgid->pid mapping in the same hash entry by modulo adding
// the pid in value and removing it by subtracting. By the time we need to
// lookup the pid by the tgid, there will be only one pid left in the hash entry.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t); // tgid
	__type(value, u64); // sum of pids
	__uint(max_entries, 1024);
} ig_pid_by_tgid SEC(".maps");

// This function should be called while entering the `execve` syscall,
// must be used in pair with `gadget_get_exec_caller_pid`.
static __always_inline void gadget_enter_exec()
{
	u64 zero64 = 0;
	u64 pid_tgid;
	pid_t pid, tgid;
	u64 *pid_sum;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = (pid_t)pid_tgid;
	tgid = pid_tgid >> 32;

	bpf_map_update_elem(&ig_pid_by_tgid, &tgid, &zero64, BPF_NOEXIST);

	pid_sum = bpf_map_lookup_elem(&ig_pid_by_tgid, &tgid);
	if (!pid_sum)
		return;

	__atomic_add_fetch(pid_sum, (u64)pid, __ATOMIC_RELAXED);
}

// This function should be called while exiting the `execve` syscall,
// argument retval: the return value of `execve` syscall,
// return value: the PID of the caller of `execve` syscall on success, zero on failure.
static __always_inline pid_t gadget_get_exec_caller_pid(long retval)
{
	u64 pid_tgid;
	pid_t pid, tgid;
	pid_t enter_pid;
	u64 *pid_sum;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = (pid_t)pid_tgid;
	tgid = pid_tgid >> 32;

	pid_sum = bpf_map_lookup_elem(&ig_pid_by_tgid, &tgid);
	if (!pid_sum)
		return 0;

	// sys_enter_execve and sys_exit_execve might be called from different
	// threads. We need to lookup the pid from the tgid.
	enter_pid = (retval == 0) ? (pid_t)*pid_sum : pid;

	// Remove the tgid->pid mapping if the value reaches 0
	// or the execve() call was successful
	__atomic_add_fetch(pid_sum, (u64)-pid, __ATOMIC_RELAXED);
	if (*pid_sum == 0 || retval == 0)
		bpf_map_delete_elem(&ig_pid_by_tgid, &tgid);

	return enter_pid;
}

#endif /* __EXEC_FIXES_H */
