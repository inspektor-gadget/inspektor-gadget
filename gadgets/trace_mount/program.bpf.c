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
#define FS_NAME_LEN 8
#define DATA_LEN 512
#define PATH_MAX 4096

enum op {
	MOUNT,
	UMOUNT,
};

enum flags_set : u64 {
	MS_RDONLY = 0x00000001,
	MS_NOSUID = 0x00000002,
	MS_NODEV = 0x00000004,
	MS_NOEXEC = 0x00000008,
	MS_SYNCHRONOUS = 0x00000010,
	MS_REMOUNT = 0x00000020,
	MS_MANDLOCK = 0x00000040,
	MS_DIRSYNC = 0x00000080,
	MS_NOSYMFOLLOW = 0x00000100,
	MS_NOATIME = 0x00000200,
	MS_NODIRATIME = 0x00000400,
	MS_BIND = 0x00000800,
	MS_MOVE = 0x00001000,
	MS_REC = 0x00002000,
	MS_VERBOSE = 0x00004000,
	MS_SILENT = 0x00008000,
	MS_POSIXACL = 0x00010000,
	MS_UNBINDABLE = 0x00020000,
	MS_PRIVATE = 0x00040000,
	MS_SLAVE = 0x00080000,
	MS_SHARED = 0x00100000,
	MS_RELATIME = 0x00200000,
	MS_KERNMOUNT = 0x00400000,
	MS_I_VERSION = 0x00800000,
	MS_STRICTATIME = 0x01000000,
	MS_LAZYTIME = 0x02000000,
	MS_SUBMOUNT = 0x04000000,
	MS_NOREMOTELOCK = 0x08000000,
	MS_NOSEC = 0x10000000,
	MS_BORN = 0x20000000,
	MS_ACTIVE = 0x40000000,
	MS_NOUSER = 0x80000000,
};

struct arg {
	__u64 ts;
	enum flags_set flags;
	const char *src;
	const char *dest;
	const char *fs;
	const char *data;
	enum op op;
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

	__u64 delta;
	enum flags_set flags_raw;
	gadget_errno error_raw;
	char fs[FS_NAME_LEN];
	char src[PATH_MAX];
	char dest[PATH_MAX];
	char data[DATA_LEN];
	enum op op_raw;
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
				       const char *fs, enum flags_set flags,
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
	__u64 uid_gid = bpf_get_current_uid_gid();
	struct arg *argp;
	struct event *eventp;

	argp = bpf_map_lookup_elem(&args, &tid);
	if (!argp)
		return 0;

	eventp = gadget_reserve_buf(&events, sizeof(*eventp));
	if (!eventp)
		goto cleanup;

	eventp->mntns_id = gadget_get_mntns_id();
	eventp->timestamp_raw = bpf_ktime_get_boot_ns();
	eventp->delta = bpf_ktime_get_ns() - argp->ts;
	eventp->flags_raw = argp->flags;
	eventp->pid = pid;
	eventp->tid = tid;
	eventp->uid = (u32)uid_gid;
	eventp->gid = (u32)(uid_gid >> 32);
	eventp->error_raw = -ret;
	eventp->op_raw = argp->op;
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
	enum flags_set flags = (enum flags_set)ctx->args[3];
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
	enum flags_set flags = (enum flags_set)ctx->args[1];

	return probe_entry(NULL, dest, NULL, flags, NULL, UMOUNT);
}

SEC("tracepoint/syscalls/sys_exit_umount")
int ig_umount_x(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
