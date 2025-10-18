// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Shaheer Ahmad */

#include <vmlinux.h>
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
	OTHER
};

// Regular and Directory by default
const volatile u32 file_type_mask = (1U << REGULAR) | (1U << DIRECTORY);

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
	gadget_file_mode mode_raw;
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

	if (gadget_should_discard_data(
		    task->nsproxy->mnt_ns->ns.inum, task->tgid, task->pid,
		    task->comm, task->cred->uid.val, task->cred->gid.val))
		return 0;

	info.mntns_id = task->nsproxy->mnt_ns->ns.inum;
	__builtin_memcpy(info.comm, task->comm, TASK_COMM_LEN);
	info.pid = task->tgid;
	info.tid = task->pid;
	info.fd = ctx->fd;
	info.inode = BPF_CORE_READ(file, f_inode, i_ino);
	info.flags_raw = BPF_CORE_READ(file, f_flags);
	info.mode_raw = BPF_CORE_READ(file, f_mode);

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
