// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021-2024 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

enum code {
	SECCOMP_RET_KILL_PROCESS = 0x80000000,
	SECCOMP_RET_KILL_THREAD = 0x00000000,
	SECCOMP_RET_KILL = 0x00000000,
	SECCOMP_RET_TRAP = 0x00030000,
	SECCOMP_RET_ERRNO = 0x00050000,
	SECCOMP_RET_USER_NOTIF = 0x7fc00000,
	SECCOMP_RET_TRACE = 0x7ff00000,
	SECCOMP_RET_LOG = 0x7ffc0000,
	SECCOMP_RET_ALLOW = 0x7fff0000,
	SECCOMP_RET_ACTION_FULL = 0xffff0000,
};

struct event {
	gadget_timestamp timestamp_raw;
	gadget_mntns_id mntns_id;

	gadget_comm comm[TASK_COMM_LEN];
	// user-space terminology for pid and tid
	gadget_pid pid;
	gadget_tid tid;
	gadget_uid uid;
	gadget_gid gid;

	gadget_syscall syscall_raw;
	enum code code_raw;
};

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(seccomp, events, event);

SEC("kprobe/audit_seccomp")
int ig_audit_secc(struct pt_regs *ctx)
{
	unsigned long syscall = PT_REGS_PARM1(ctx);
	int code = PT_REGS_PARM3(ctx);
	struct event *event;
	__u64 pid_tgid;
	__u64 uid_gid;

	__u64 mntns_id = gadget_get_mntns_id();
	if (mntns_id == 0)
		return 0;

	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	uid_gid = bpf_get_current_uid_gid();

	event->timestamp_raw = bpf_ktime_get_boot_ns();
	event->pid = (__u32)(pid_tgid >> 32);
	event->tid = (__u32)pid_tgid;
	event->uid = (__u32)uid_gid;
	event->gid = (__u32)(uid_gid >> 32);
	event->mntns_id = mntns_id;
	event->syscall_raw = syscall;
	event->code_raw = code;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

char _license[] SEC("license") = "GPL";
