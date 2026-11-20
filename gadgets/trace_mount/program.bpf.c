/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2021 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/filesystem.h>

#define MAX_ENTRIES 10240
#define FS_NAME_LEN 8
#define DATA_LEN 512

enum op {
	MOUNT,
	UMOUNT,
	FSOPEN,
	FSCONFIG,
	FSMOUNT,
	MOVE_MOUNT,
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

union sys_arg {
	struct {
		enum flags_set flags;
		const char *src;
		const char *dest;
		const char *fs;
		const char *data;
	} mount;
	struct {
		enum flags_set flags;
		const char *dest;
	} umount;
	struct {
		const char *fs;
		__u32 flags;
	} fsopen;
	struct {
		int fd;
		unsigned int cmd;
		const char *key;
		const char *value;
		int aux;
	} fsconfig;
	struct {
		int fs_fd;
		__u32 flags;
		__u32 attr_flags;
	} fsmount;
	struct {
		int from_dfd;
		const char *from_pathname;
		int to_dfd;
		const char *to_pathname;
		__u32 flags;
	} move_mount;
};

struct arg {
	__u64 ts;
	enum op op;
	union sys_arg sys;
};

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;
	gadget_netns_id netns_id;

	gadget_duration delta_raw;
	enum flags_set flags_raw;
	gadget_errno error_raw;
	char fs[FS_NAME_LEN];
	char src[GADGET_PATH_MAX];
	char dest[GADGET_PATH_MAX];
	char data[DATA_LEN];
	enum op op_raw;

	/* fsopen(2), fsconfig(2), fsmount(2) and move_mount(2) specific fields.
	 * They are hidden and only used to build the call column. */
	__s32 fd; /* fsconfig fd, fsmount fs_fd, move_mount from_dfd */
	__s32 to_fd; /* move_mount to_dfd */
	__u32 cmd; /* fsconfig cmd */
	__s32 aux; /* fsconfig aux */
	__u32 fsflags; /* fsopen, fsmount or move_mount flags */
	__u32 attr_flags; /* fsmount attr_flags */
	char key[DATA_LEN]; /* fsconfig key */
	char value[DATA_LEN]; /* fsconfig value */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct arg);
} args SEC(".maps");

// Roughly 30 events
GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(mount, events, event);

static __always_inline int probe_entry(union sys_arg *sys_arg, enum op op)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)pid_tgid;
	struct arg arg = {};

	if (gadget_should_discard_data_current())
		return 0;

	arg.ts = bpf_ktime_get_ns();
	arg.op = op;
	__builtin_memcpy(&arg.sys, sys_arg, sizeof(*sys_arg));
	bpf_map_update_elem(&args, &tid, &arg, BPF_ANY);

	return 0;
};

static __always_inline void read_user_str(char *dst, __u32 size,
					  const char *src)
{
	if (src)
		bpf_probe_read_user_str(dst, size, src);
}

static int probe_exit(void *ctx, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)pid_tgid;
	struct arg *argp;
	struct event *eventp;

	argp = bpf_map_lookup_elem(&args, &tid);
	if (!argp)
		return 0;

	eventp = gadget_reserve_buf(&events, sizeof(*eventp));
	if (!eventp)
		goto cleanup;

	gadget_process_populate(&eventp->proc);
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	eventp->netns_id = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
	eventp->timestamp_raw = bpf_ktime_get_boot_ns();
	eventp->delta_raw = bpf_ktime_get_ns() - argp->ts;
	eventp->error_raw = -ret;
	eventp->op_raw = argp->op;

	/* The buffer may be reused, clear all op-specific fields first. */
	eventp->flags_raw = 0;
	eventp->src[0] = '\0';
	eventp->dest[0] = '\0';
	eventp->fs[0] = '\0';
	eventp->data[0] = '\0';
	eventp->key[0] = '\0';
	eventp->value[0] = '\0';
	eventp->fd = 0;
	eventp->to_fd = 0;
	eventp->cmd = 0;
	eventp->aux = 0;
	eventp->fsflags = 0;
	eventp->attr_flags = 0;

	switch (argp->op) {
	case MOUNT:
		eventp->flags_raw = argp->sys.mount.flags;
		read_user_str(eventp->src, sizeof(eventp->src),
			      argp->sys.mount.src);
		read_user_str(eventp->dest, sizeof(eventp->dest),
			      argp->sys.mount.dest);
		read_user_str(eventp->fs, sizeof(eventp->fs),
			      argp->sys.mount.fs);
		read_user_str(eventp->data, sizeof(eventp->data),
			      argp->sys.mount.data);
		break;
	case UMOUNT:
		eventp->flags_raw = argp->sys.umount.flags;
		read_user_str(eventp->dest, sizeof(eventp->dest),
			      argp->sys.umount.dest);
		break;
	case FSOPEN:
		eventp->fsflags = argp->sys.fsopen.flags;
		read_user_str(eventp->fs, sizeof(eventp->fs),
			      argp->sys.fsopen.fs);
		break;
	case FSCONFIG:
		eventp->fd = argp->sys.fsconfig.fd;
		eventp->cmd = argp->sys.fsconfig.cmd;
		eventp->aux = argp->sys.fsconfig.aux;
		read_user_str(eventp->key, sizeof(eventp->key),
			      argp->sys.fsconfig.key);
		/* value is only a string for FSCONFIG_SET_STRING (1) and
		 * FSCONFIG_SET_PATH{,_EMPTY} (3, 4). */
		if (argp->sys.fsconfig.cmd == 1 ||
		    argp->sys.fsconfig.cmd == 3 || argp->sys.fsconfig.cmd == 4)
			read_user_str(eventp->value, sizeof(eventp->value),
				      argp->sys.fsconfig.value);
		break;
	case FSMOUNT:
		eventp->fd = argp->sys.fsmount.fs_fd;
		eventp->fsflags = argp->sys.fsmount.flags;
		eventp->attr_flags = argp->sys.fsmount.attr_flags;
		break;
	case MOVE_MOUNT:
		eventp->fd = argp->sys.move_mount.from_dfd;
		eventp->to_fd = argp->sys.move_mount.to_dfd;
		eventp->fsflags = argp->sys.move_mount.flags;
		read_user_str(eventp->src, sizeof(eventp->src),
			      argp->sys.move_mount.from_pathname);
		read_user_str(eventp->dest, sizeof(eventp->dest),
			      argp->sys.move_mount.to_pathname);
		break;
	}

	gadget_submit_buf(ctx, &events, eventp, sizeof(*eventp));

cleanup:
	bpf_map_delete_elem(&args, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mount")
int ig_mount_e(struct syscall_trace_enter *ctx)
{
	union sys_arg arg = {};

	arg.mount.src = (const char *)ctx->args[0];
	arg.mount.dest = (const char *)ctx->args[1];
	arg.mount.fs = (const char *)ctx->args[2];
	arg.mount.flags = (enum flags_set)ctx->args[3];
	arg.mount.data = (const char *)ctx->args[4];

	return probe_entry(&arg, MOUNT);
}

SEC("tracepoint/syscalls/sys_exit_mount")
int ig_mount_x(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_umount")
int ig_umount_e(struct syscall_trace_enter *ctx)
{
	union sys_arg arg = {};

	arg.umount.dest = (const char *)ctx->args[0];
	arg.umount.flags = (enum flags_set)ctx->args[1];

	return probe_entry(&arg, UMOUNT);
}

SEC("tracepoint/syscalls/sys_exit_umount")
int ig_umount_x(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

/* fsopen(2), fsconfig(2), fsmount(2) and move_mount(2) were introduced in
 * Linux 5.2:
 * https://github.com/torvalds/linux/commit/24dcb3d90a1f ("vfs: syscall: Add fsopen() to prepare for superblock creation")
 * https://github.com/torvalds/linux/commit/ecdab150fddb ("vfs: syscall: Add fsconfig() for configuring and managing a context")
 * https://github.com/torvalds/linux/commit/93766fbd2696 ("vfs: syscall: Add fsmount() to create a mount for a superblock")
 * https://github.com/torvalds/linux/commit/2db154b3ea8e ("vfs: syscall: Add move_mount(2) to move mounts around")
 */
SEC("tracepoint/syscalls/sys_enter_fsopen")
int ig_fsopen_e(struct syscall_trace_enter *ctx)
{
	union sys_arg arg = {};

	arg.fsopen.fs = (const char *)ctx->args[0];
	arg.fsopen.flags = (__u32)ctx->args[1];

	return probe_entry(&arg, FSOPEN);
}

SEC("tracepoint/syscalls/sys_exit_fsopen")
int ig_fsopen_x(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_fsconfig")
int ig_fsconfig_e(struct syscall_trace_enter *ctx)
{
	union sys_arg arg = {};

	arg.fsconfig.fd = (int)ctx->args[0];
	arg.fsconfig.cmd = (unsigned int)ctx->args[1];
	arg.fsconfig.key = (const char *)ctx->args[2];
	arg.fsconfig.value = (const char *)ctx->args[3];
	arg.fsconfig.aux = (int)ctx->args[4];

	return probe_entry(&arg, FSCONFIG);
}

SEC("tracepoint/syscalls/sys_exit_fsconfig")
int ig_fsconfig_x(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_fsmount")
int ig_fsmount_e(struct syscall_trace_enter *ctx)
{
	union sys_arg arg = {};

	arg.fsmount.fs_fd = (int)ctx->args[0];
	arg.fsmount.flags = (__u32)ctx->args[1];
	arg.fsmount.attr_flags = (__u32)ctx->args[2];

	return probe_entry(&arg, FSMOUNT);
}

SEC("tracepoint/syscalls/sys_exit_fsmount")
int ig_fsmount_x(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_move_mount")
int ig_move_mount_e(struct syscall_trace_enter *ctx)
{
	union sys_arg arg = {};

	arg.move_mount.from_dfd = (int)ctx->args[0];
	arg.move_mount.from_pathname = (const char *)ctx->args[1];
	arg.move_mount.to_dfd = (int)ctx->args[2];
	arg.move_mount.to_pathname = (const char *)ctx->args[3];
	arg.move_mount.flags = (__u32)ctx->args[4];

	return probe_entry(&arg, MOVE_MOUNT);
}

SEC("tracepoint/syscalls/sys_exit_move_mount")
int ig_move_mount_x(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
