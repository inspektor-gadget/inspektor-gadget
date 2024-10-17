// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021~2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

struct value {
	gadget_mntns_id mntns_id;
	int sig;
};

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;

	__u32 tpid;

	gadget_signal sig_raw;
	gadget_errno error_raw;
};

const volatile pid_t filtered_pid = 0;
const volatile int target_signal = 0;
const volatile bool failed_only = false;
const volatile bool kill_only = false;

GADGET_PARAM(filtered_pid);
GADGET_PARAM(target_signal);
GADGET_PARAM(failed_only);
GADGET_PARAM(kill_only);

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct value);
} values SEC(".maps");

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(signal, events, event);

static int probe_entry(pid_t tpid, int sig)
{
	struct value v = {};
	__u64 pid_tgid;
	__u32 pid, tid;
	u64 mntns_id;

	if (!kill_only)
		return 0;

	mntns_id = gadget_get_mntns_id();

	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	if (target_signal && sig != target_signal)
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	tid = (__u32)pid_tgid;
	if (filtered_pid && pid != filtered_pid)
		return 0;

	v.sig = sig;
	v.mntns_id = mntns_id;
	bpf_map_update_elem(&values, &tid, &v, BPF_ANY);
	return 0;
}

static int probe_exit(void *ctx, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)pid_tgid;
	struct event *eventp;
	struct value *vp;

	if (!kill_only)
		return 0;

	vp = bpf_map_lookup_elem(&values, &tid);
	if (!vp)
		return 0;

	if (failed_only && ret >= 0)
		goto cleanup;

	eventp = gadget_reserve_buf(&events, sizeof(*eventp));
	if (!eventp)
		goto cleanup;

	gadget_process_populate(&eventp->proc);
	eventp->error_raw = -ret;
	eventp->timestamp_raw = bpf_ktime_get_boot_ns();
	eventp->sig_raw = vp->sig;
	gadget_submit_buf(ctx, &events, eventp, sizeof(*eventp));

cleanup:
	bpf_map_delete_elem(&values, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int ig_sig_kill_e(struct syscall_trace_enter *ctx)
{
	pid_t tpid = (pid_t)ctx->args[0];
	int sig = (int)ctx->args[1];

	return probe_entry(tpid, sig);
}

SEC("tracepoint/syscalls/sys_exit_kill")
int ig_sig_kill_x(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_tkill")
int ig_sig_tkill_e(struct syscall_trace_enter *ctx)
{
	pid_t tpid = (pid_t)ctx->args[0];
	int sig = (int)ctx->args[1];

	return probe_entry(tpid, sig);
}

SEC("tracepoint/syscalls/sys_exit_tkill")
int ig_sig_tkill_x(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_tgkill")
int ig_sig_tgkill_e(struct syscall_trace_enter *ctx)
{
	pid_t tpid = (pid_t)ctx->args[1];
	int sig = (int)ctx->args[2];

	return probe_entry(tpid, sig);
}

SEC("tracepoint/syscalls/sys_exit_tgkill")
int ig_sig_tgkill_x(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, ctx->ret);
}

SEC("tracepoint/signal/signal_generate")
int ig_sig_generate(struct trace_event_raw_signal_generate *ctx)
{
	struct event *event;
	pid_t tpid = ctx->pid;
	int ret = ctx->errno;
	int sig = ctx->sig;
	__u64 pid_tgid;
	__u32 pid;

	if (kill_only)
		return 0;

	if (gadget_should_discard_mntns_id(gadget_get_mntns_id()))
		return 0;

	if (failed_only && ret == 0)
		return 0;

	if (target_signal && sig != target_signal)
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	if (filtered_pid && pid != filtered_pid)
		return 0;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	gadget_process_populate(&event->proc);
	event->tpid = tpid;
	event->sig_raw = sig;
	event->error_raw = -ret;
	event->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_submit_buf(ctx, &events, event, sizeof(*event));
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
