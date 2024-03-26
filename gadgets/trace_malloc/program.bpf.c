// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>

enum memop {
	MALLOC,
	FREE,
};

struct event {
	gadget_mntns_id mntns_id;
	__u32 pid;
	__u8 comm[TASK_COMM_LEN];
	enum memop operation;
	__u64 addr;
};

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(malloc, events, event);

static __always_inline int submit_memop_event(struct pt_regs *ctx,
					      enum memop operation, __u64 addr)
{
	u64 mntns_id;
	struct event *event;

	mntns_id = gadget_get_mntns_id();
	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	event->mntns_id = mntns_id;
	event->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(event->comm, sizeof(event->comm));
	event->operation = operation;
	event->addr = addr;

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

SEC("uretprobe/libc:malloc")
int trace_uprobe_malloc(struct pt_regs *ctx)
{
	return submit_memop_event(ctx, MALLOC, PT_REGS_RC(ctx));
}

SEC("uprobe/libc:free")
int trace_uprobe_free(struct pt_regs *ctx)
{
	return submit_memop_event(ctx, FREE, PT_REGS_PARM1(ctx));
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
