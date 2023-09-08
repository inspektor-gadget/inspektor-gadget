// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 The Inspektor Gadget authors */

/* This BPF program uses the GPL-restricted function bpf_probe_read*().
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "audit-seccomp.h"
#include <gadget/mntns_filter.h>

/* The stack is limited, so use a map to build the event */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct event);
} tmp_event SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("kprobe/audit_seccomp")
int ig_audit_secc(struct pt_regs *ctx)
{
	unsigned long syscall = PT_REGS_PARM1(ctx);
	int code = PT_REGS_PARM3(ctx);

	__u64 mntns_id = gadget_get_mntns_id();
	if (mntns_id == 0)
		return 0;

	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	__u32 zero = 0;
	struct event *event = bpf_map_lookup_elem(&tmp_event, &zero);
	if (!event)
		return 0;

	event->timestamp = bpf_ktime_get_boot_ns();
	event->pid = bpf_get_current_pid_tgid();
	event->mntns_id = mntns_id;
	event->syscall = syscall;
	event->code = code;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
			      sizeof(*event));
	return 0;
}

char _license[] SEC("license") = "GPL";
