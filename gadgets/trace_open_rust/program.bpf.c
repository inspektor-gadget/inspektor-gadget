// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
// Copyright (c) 2020 Netflix

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/user_stack_map.h>

#define TASK_RUNNING 0
#define NAME_MAX 255

struct args_t {
	const char *fname;
	int flags;
	__u16 mode;
};

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;

	gadget_errno error_raw;
	__u32 fd;
	int flags_raw;
	__u16 mode_raw;
	struct gadget_user_stack ustack;
	char fname[NAME_MAX];
};

const volatile bool targ_failed = false;
GADGET_PARAM(targ_failed);

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct args_t);
} start SEC(".maps");

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(open, events, event);

static __always_inline int trace_enter(const char *filename, int flags,
				       __u16 mode)
{
	__u64 pid = bpf_get_current_pid_tgid();

	if (gadget_should_discard_data_current())
		return 0;

	struct args_t args = {};
	args.fname = filename;
	args.flags = flags;
	args.mode = mode;
	bpf_map_update_elem(&start, &pid, &args, 0);

	return 0;
}

#ifndef __TARGET_ARCH_arm64
SEC("tracepoint/syscalls/sys_enter_open")
int ig_open_e(struct syscall_trace_enter *ctx)
{
	return trace_enter((const char *)ctx->args[0], (int)ctx->args[1],
			   (__u16)ctx->args[2]);
}
#endif /* !__TARGET_ARCH_arm64 */

SEC("tracepoint/syscalls/sys_enter_openat")
int ig_openat_e(struct syscall_trace_enter *ctx)
{
	return trace_enter((const char *)ctx->args[1], (int)ctx->args[2],
			   (__u16)ctx->args[3]);
}

static __always_inline int trace_exit(struct syscall_trace_exit *ctx)
{
	struct event *event;
	struct args_t *ap;
	long int ret;
	__u32 fd;
	__s32 errval;
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	// pid from kernel po
	u32 pid = (u32)pid_tgid;

	ap = bpf_map_lookup_elem(&start, &pid);
	if (!ap)
		return 0; /* missed entry */
	ret = ctx->ret;
	if (targ_failed && ret >= 0)
		goto cleanup; /* want failed only */

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		goto cleanup;

	fd = 0;
	errval = 0;
	if (ret >= 0) {
		fd = ret;
	} else {
		errval = -ret;
	}

	/* event data */
	gadget_process_populate(&event->proc);
	gadget_get_user_stack(ctx, &event->ustack);

	bpf_probe_read_user_str(&event->fname, sizeof(event->fname), ap->fname);
	event->flags_raw = ap->flags;
	event->mode_raw = ap->mode;
	event->error_raw = errval;
	event->fd = fd;
	event->timestamp_raw = bpf_ktime_get_boot_ns();

	/* emit event */
	gadget_submit_buf(ctx, &events, event, sizeof(*event));

cleanup:
	bpf_map_delete_elem(&start, &pid);
	return 0;
}

#ifndef __TARGET_ARCH_arm64
SEC("tracepoint/syscalls/sys_exit_open")
int ig_open_x(struct syscall_trace_exit *ctx)
{
	return trace_exit(ctx);
}
#endif /* !__TARGET_ARCH_arm64 */

SEC("tracepoint/syscalls/sys_exit_openat")
int ig_openat_x(struct syscall_trace_exit *ctx)
{
	return trace_exit(ctx);
}

char LICENSE[] SEC("license") = "GPL";
