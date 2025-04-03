// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021-2024 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/user_stack_map.h>

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
	struct gadget_process proc;

	gadget_syscall syscall_raw;
	enum code code_raw;
	struct gadget_user_stack ustack;
};

const volatile bool collect_ustack = false;
GADGET_PARAM(collect_ustack);

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(seccomp, events, event);

SEC("kprobe/audit_seccomp")
int ig_audit_secc(struct pt_regs *ctx)
{
	unsigned long syscall = PT_REGS_PARM1(ctx);
	int code = PT_REGS_PARM3(ctx);
	struct event *event;

	if (gadget_should_discard_data_current())
		return 0;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	gadget_process_populate(&event->proc);
	event->timestamp_raw = bpf_ktime_get_boot_ns();
	event->syscall_raw = syscall;
	event->code_raw = code;
	gadget_get_user_stack(ctx, &event->ustack, collect_ustack);

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

char _license[] SEC("license") = "GPL";
