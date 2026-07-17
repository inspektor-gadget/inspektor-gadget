// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Shaheer Ahmad */

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include <gadget/macros.h>
#include <gadget/filter.h>
#include <gadget/types.h>
#include <gadget/filesystem.h>

const volatile bool paths = false;

#define MAX_PATH_LEN 256

enum file_type {
	REGULAR = 0,
	SOCKET,
	PIPE,
	BPF_MAP,
	DIRECTORY,
	CHAR_DEV,
	BLOCK_DEV,
	SYMLINK,
	BPF_LINK,
	BPF_PROG,
	EVENTFD,
	TIMERFD,
	SIGNALFD,
	EPOLL,
	PERF_EVENT,
	USERFAULTFD,
	PIDFD,
	IO_URING,
	FANOTIFY,
	INOTIFY,
	OTHER
};

/*
 * Several file types are exposed to userspace through anonymous inodes, whose
 * i_mode carries permission bits only (no S_IFMT type bits), so they cannot be
 * classified by mode. Instead we compare file->f_op against the kernel's
 * per-type file_operations tables. cilium/ebpf resolves these __ksym externs
 * from /proc/kallsyms at load time. They are __weak so that a kernel missing the
 * symbol (or a process without CAP_SYSLOG) resolves them to NULL and simply
 * falls back to the regular mode-based classification.
 *
 * Requires: Linux >= 5.11 for __ksym weak data relocations. See the gadget's
 * README.mdx (## Requirements) for details.
 */
extern void bpf_map_fops __ksym __weak;
extern void bpf_link_fops __ksym __weak;
extern void bpf_prog_fops __ksym __weak;
extern void eventfd_fops __ksym __weak;
extern void timerfd_fops __ksym __weak;
extern void signalfd_fops __ksym __weak;
extern void eventpoll_fops __ksym __weak;
extern void perf_fops __ksym __weak;
extern void userfaultfd_fops __ksym __weak;
extern void pidfd_fops __ksym __weak;
extern void io_uring_fops __ksym __weak;
extern void fanotify_fops __ksym __weak;
extern void inotify_fops __ksym __weak;

// Show all file types by default; use file_type_mask to filter.
const volatile u32 file_type_mask = 0xffffffff;

struct gadget_file {
	gadget_mntns_id mntns_id;
	char comm[TASK_COMM_LEN];
	gadget_pid pid;
	gadget_tid tid;
	__u32 fd;
	enum file_type type_raw;
	char path[MAX_PATH_LEN];
	__u64 inode;
	gadget_file_flags flags_raw;
};

#define S_IFMT 00170000 /* bitmask for the file type bitfields */
#define S_IFSOCK 0140000 /* socket */
#define S_IFLNK 0120000 /* symbolic link */
#define S_IFREG 0100000 /* regular file */
#define S_IFBLK 0060000 /* block device */
#define S_IFDIR 0040000 /* directory */
#define S_IFCHR 0020000 /* character device */
#define S_IFIFO 0010000 /* FIFO */

GADGET_PARAM(file_type_mask);
GADGET_PARAM(paths);

GADGET_SNAPSHOTTER(files, gadget_file, ig_snap_file);

static __always_inline u32 classify_file_type(struct file *file)
{
	// Anonymous-inode file types (bpf objects, eventfd, epoll, io_uring, ...)
	// carry no S_IFMT type bits in i_mode, so identify them by their
	// file_operations table (resolved via the __ksym externs above). The
	// &sym guard skips symbols that were not resolved (older kernel or no
	// CAP_SYSLOG), letting classification fall back to the mode switch below.
	const void *fop = BPF_CORE_READ(file, f_op);

#define MATCH_FOP(sym, type)         \
	if (&sym && fop == &sym)     \
		return type;

	MATCH_FOP(bpf_map_fops, BPF_MAP);
	MATCH_FOP(bpf_link_fops, BPF_LINK);
	MATCH_FOP(bpf_prog_fops, BPF_PROG);
	MATCH_FOP(eventfd_fops, EVENTFD);
	MATCH_FOP(timerfd_fops, TIMERFD);
	MATCH_FOP(signalfd_fops, SIGNALFD);
	MATCH_FOP(eventpoll_fops, EPOLL);
	MATCH_FOP(perf_fops, PERF_EVENT);
	MATCH_FOP(userfaultfd_fops, USERFAULTFD);
	MATCH_FOP(pidfd_fops, PIDFD);
	MATCH_FOP(io_uring_fops, IO_URING);
	MATCH_FOP(fanotify_fops, FANOTIFY);
	MATCH_FOP(inotify_fops, INOTIFY);

#undef MATCH_FOP

	u32 mode = BPF_CORE_READ(file, f_inode, i_mode) & S_IFMT;

	switch (mode) {
	case S_IFREG:
		return REGULAR;
	case S_IFDIR:
		return DIRECTORY;
	case S_IFIFO:
		return PIPE;
	case S_IFSOCK:
		return SOCKET;
	case S_IFCHR:
		return CHAR_DEV;
	case S_IFBLK:
		return BLOCK_DEV;
	case S_IFLNK:
		return SYMLINK;
	default:
		return OTHER;
	}
}

static __always_inline int copy_dentry_name(struct path *path, char *buf,
					    int buf_len)
{
	// barebones implementation to get the first part of the dentry name
	struct dentry *dentry;
	const unsigned char *name;
	u32 name_len;

	if (!path || !buf)
		return -1;

	dentry = BPF_CORE_READ(path, dentry);
	name = BPF_CORE_READ(dentry, d_name.name);
	name_len = BPF_CORE_READ(dentry, d_name.len);

	if (name_len >= buf_len)
		name_len = buf_len - 1;

	if (bpf_probe_read_kernel_str(buf, name_len + 1, name) < 0)
		return -1;

	return 0;
}

/*  
   * BPF iterator program: one invocation per (task, file)  
   */
SEC("iter/task_file")
int ig_snap_file(struct bpf_iter__task_file *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct file *file = ctx->file;
	struct gadget_file info;

	if (!task || !file)
		return 0;

	__u32 uid = BPF_CORE_READ(task, cred, uid.val);
	__u32 gid = BPF_CORE_READ(task, cred, gid.val);

	if (gadget_should_discard_data(task->nsproxy->mnt_ns->ns.inum,
				       task->tgid, task->pid, task->comm, uid,
				       gid))
		return 0;

	info.mntns_id = task->nsproxy->mnt_ns->ns.inum;
	__builtin_memcpy(info.comm, task->comm, TASK_COMM_LEN);
	info.pid = task->tgid;
	info.tid = task->pid;
	info.fd = ctx->fd;
	info.inode = BPF_CORE_READ(file, f_inode, i_ino);
	info.flags_raw = BPF_CORE_READ(file, f_flags);

	info.type_raw = classify_file_type(file);

	if (!((1U << info.type_raw) & file_type_mask))
		return 0; // skip this file
	if (paths) {
		char *file_path;
		file_path = get_path_str(&file->f_path);
		bpf_probe_read_kernel_str(info.path, sizeof(info.path),
					  file_path);
	} else {
		copy_dentry_name(&file->f_path, info.path, MAX_PATH_LEN);
	}
	bpf_seq_write(seq, &info, sizeof(info));
	return 0;
}

char _license[] SEC("license") = "GPL";
