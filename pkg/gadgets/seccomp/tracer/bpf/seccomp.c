// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 The Inspektor Gadget authors */

/* This BPF program uses the GPL-restricted function bpf_probe_read*().
 */

#include <vmlinux/vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "seccomp-common.h"

#define TASK_COMM_LEN 16
#define TS_COMPAT 0x0002

// Seccomp syscall number from
// https://github.com/torvalds/linux/blob/v5.12/tools/testing/selftests/seccomp/seccomp_bpf.c#L115
// Only x86_64 is supported for now.
#ifndef __NR_seccomp
#define __NR_seccomp 317
#endif

#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER         1
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, unsigned char[SYSCALLS_MAP_VALUE_SIZE]);
	__uint(max_entries, 1024);
} syscalls_per_mntns SEC(".maps");

static __always_inline int is_x86_compat(struct task_struct *task)
{
	return !!(BPF_CORE_READ(task, thread_info.status) & TS_COMPAT);
}

SEC("raw_tracepoint/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	struct pt_regs regs = {};
	unsigned int id;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	bpf_probe_read(&regs, sizeof(struct pt_regs), (void*)ctx->args[0]);
	id = ctx->args[1];

	if (is_x86_compat(task)) {
		return 0;
	}

	if (id < 0 || id >= SYSCALLS_COUNT)
		return 0;

	char comm[TASK_COMM_LEN];
	bpf_get_current_comm(comm, sizeof(comm));
	int is_runc = comm[0] == 'r' && comm[1] == 'u' && comm[2] == 'n' && comm[3] == 'c';

	__u64 mntns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	if (mntns == 0) {
		return 0;
	}

	unsigned char *syscall_bitmap = bpf_map_lookup_elem(&syscalls_per_mntns, &mntns);
	if (syscall_bitmap == 0) {
		__u64 zero = 0;
		unsigned char *blank_bitmap = bpf_map_lookup_elem(&syscalls_per_mntns, &zero);
		if (blank_bitmap == 0)
			return 0;
		bpf_map_update_elem(&syscalls_per_mntns, &mntns, blank_bitmap, BPF_NOEXIST);

		syscall_bitmap = bpf_map_lookup_elem(&syscalls_per_mntns, &mntns);
		if (syscall_bitmap == 0)
			return 0;
	}

	if (is_runc) {
		/* libseccomp makes invalid calls to seccomp() to determine the api
		 * level. Ignore those. */
		if (id == __NR_seccomp &&
		PT_REGS_PARM1(&regs) == SECCOMP_SET_MODE_FILTER &&
		PT_REGS_PARM3(&regs) != 0) {
			/* Mark this container: seccomp has been called. */
			syscall_bitmap[SYSCALLS_COUNT] = 1;
			return 0;
		}
		/* Don't register syscalls performed by runc before the seccomp policy is actually installed */
		if (syscall_bitmap[SYSCALLS_COUNT] == 0)
			return 0;
	}

	syscall_bitmap[id] = 0x01;

	return 0;
}

char _license[] SEC("license") = "GPL";
