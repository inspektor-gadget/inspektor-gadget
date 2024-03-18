// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/types.h>

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

GADGET_TRACER(open, events, event);

static __always_inline int submit_memop_event(struct pt_regs *ctx,
					      enum memop operation, __u64 addr)
{
	struct event *event;
	struct task_struct *task;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	task = (struct task_struct *)bpf_get_current_task();

	event->mntns_id = (u64)BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	event->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(event->comm, sizeof(event->comm));
	event->operation = operation;
	event->addr = addr;

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

SEC("uretprobe//usr/lib/libc.so.6:malloc")
int trace_uprobe_malloc(struct pt_regs *ctx)
{
	return submit_memop_event(ctx, MALLOC, PT_REGS_RC(ctx));
}

SEC("uprobe//usr/lib/libc.so.6:free")
int trace_uprobe_free(struct pt_regs *ctx)
{
	return submit_memop_event(ctx, FREE, PT_REGS_PARM1(ctx));
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
