// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
// Copyright (c) 2020 Netflix

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#define TASK_RUNNING 0
#define NAME_MAX 255
#define INVALID_UID ((uid_t) - 1)

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
	char fname[NAME_MAX];
};

const volatile pid_t targ_pid = 0;
const volatile pid_t targ_tgid = 0;
const volatile uid_t targ_uid = INVALID_UID;
const volatile bool targ_failed = false;

GADGET_PARAM(targ_tgid);
GADGET_PARAM(targ_uid);
GADGET_PARAM(targ_failed);

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct args_t);
} start SEC(".maps");

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(open, events, event);

static __always_inline bool valid_uid(uid_t uid)
{
	return uid != INVALID_UID;
}

static __always_inline bool trace_allowed(u32 tgid, u32 pid)
{
	u64 mntns_id;
	u32 uid;

	/* filters */
	if (targ_tgid && targ_tgid != tgid)
		return false;
	if (targ_pid && targ_pid != pid)
		return false;
	if (valid_uid(targ_uid)) {
		uid = (u32)bpf_get_current_uid_gid();
		if (targ_uid != uid) {
			return false;
		}
	}

	mntns_id = gadget_get_mntns_id();

	if (gadget_should_discard_mntns_id(mntns_id))
		return false;

	return true;
}

static __always_inline int trace_enter(const char *filename, int flags,
				       __u16 mode)
{
	u64 id = bpf_get_current_pid_tgid();
	/* use kernel terminology here for tgid/pid: */
	u32 tgid = id >> 32;
	u32 pid = id;

	/* store arg info for later lookup */
	if (trace_allowed(tgid, pid)) {
		struct args_t args = {};
		args.fname = filename;
		args.flags = flags;
		args.mode = mode;
		bpf_map_update_elem(&start, &pid, &args, 0);
	}
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
