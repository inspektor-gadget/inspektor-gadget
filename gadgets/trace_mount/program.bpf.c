/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2021 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#define MAX_ENTRIES 10240
#define TASK_COMM_LEN 16
#define FS_NAME_LEN 8
#define DATA_LEN 512
#define PATH_MAX 4096

enum op {
	MOUNT,
	UMOUNT,
};

struct arg {
	__u64 ts;
	__u64 flags;
	const char *src;
	const char *dest;
	const char *fs;
	const char *data;
	enum op op;
};

struct event {
	__u64 delta;
	__u64 flags;
	__u32 pid;
	__u32 tid;
	gadget_mntns_id mount_ns_id;
	__u64 timestamp;
	int ret;
	__u8 comm[TASK_COMM_LEN];
	__u8 fs[FS_NAME_LEN];
	__u8 src[PATH_MAX];
	__u8 dest[PATH_MAX];
	__u8 data[DATA_LEN];
	enum op op;
};

const volatile pid_t target_pid = 0;

GADGET_PARAM(target_pid);

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct arg);
} args SEC(".maps");

// Roughly 30 events
GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(mount, events, event);

// TODO: have to use "inline" to avoid this error:
// bpf/mountsnoop.bpf.c:41:12: error: defined with too many args
// static int probe_entry(const char *src, const char *dest, const char *fs,
static __always_inline int probe_entry(const char *src, const char *dest,
				       const char *fs, __u64 flags,
				       const char *data, enum op op)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct arg arg = {};
	u64 mntns_id;

	mntns_id = gadget_get_mntns_id();

	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	if (target_pid && target_pid != pid)
		return 0;

	arg.ts = bpf_ktime_get_ns();
	arg.flags = flags;
	arg.src = src;
	arg.dest = dest;
	arg.fs = fs;
	arg.data = data;
	arg.op = op;
	bpf_map_update_elem(&args, &tid, &arg, BPF_ANY);

	return 0;
};

static int probe_exit(void *ctx, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct arg *argp;
	struct event *eventp;
	int zero = 0;

	argp = bpf_map_lookup_elem(&args, &tid);
	if (!argp)
		return 0;

	eventp = gadget_reserve_buf(&events, sizeof(*eventp));
	if (!eventp)
		goto cleanup;

	eventp->mount_ns_id = gadget_get_mntns_id();
	eventp->timestamp = bpf_ktime_get_boot_ns();
	eventp->delta = bpf_ktime_get_ns() - argp->ts;
	eventp->flags = argp->flags;
	eventp->pid = pid;
	eventp->tid = tid;
	eventp->ret = ret;
	eventp->op = argp->op;
	bpf_get_current_comm(&eventp->comm, sizeof(eventp->comm));
	if (argp->src)
		bpf_probe_read_user_str(eventp->src, sizeof(eventp->src),
					argp->src);
	else
		eventp->src[0] = '\0';
	if (argp->dest)
		bpf_probe_read_user_str(eventp->dest, sizeof(eventp->dest),
					argp->dest);
	else
		eventp->dest[0] = '\0';
	if (argp->fs)
		bpf_probe_read_user_str(eventp->fs, sizeof(eventp->fs),
					argp->fs);
	else
		eventp->fs[0] = '\0';
	if (argp->data)
		bpf_probe_read_user_str(eventp->data, sizeof(eventp->data),
					argp->data);
	else
		eventp->data[0] = '\0';

	gadget_submit_buf(ctx, &events, eventp, sizeof(*eventp));

cleanup:
	bpf_map_delete_elem(&args, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mount")
int ig_mount_e(struct syscall_trace_enter *ctx)
{
	const char *src = (const char *)ctx->args[0];
	const char *dest = (const char *)ctx->args[1];
	const char *fs = (const char *)ctx->args[2];
	__u64 flags = (__u64)ctx->args[3];
	const char *data = (const char *)ctx->args[4];

	return probe_entry(src, dest, fs, flags, data, MOUNT);
}

SEC("tracepoint/syscalls/sys_exit_mount")
int ig_mount_x(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_umount")
int ig_umount_e(struct syscall_trace_enter *ctx)
{
	const char *dest = (const char *)ctx->args[0];
	__u64 flags = (__u64)ctx->args[1];

	return probe_entry(NULL, dest, NULL, flags, NULL, UMOUNT);
}

SEC("tracepoint/syscalls/sys_exit_umount")
int ig_umount_x(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
