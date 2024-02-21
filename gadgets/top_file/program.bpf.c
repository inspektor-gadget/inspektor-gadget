/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Hengqi Chen */
/* Copyright (c) 2023-2024 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include <gadget/mntns_filter.h>
#include <gadget/types.h>
#include <gadget/macros.h>

#include "stat.h"

#define PATH_MAX 4096
#define TASK_COMM_LEN 16

enum op {
	READ,
	WRITE,
};

enum type {
	R, // Regular file
	S, // Socket
	O, // Other (including pipes)
};

struct file_id {
	__u64 inode;
	__u32 dev;
	__u32 pid;
	__u32 tid;
};

struct file_stat {
	gadget_mntns_id mntns_id;
	__u64 reads;
	__u64 rbytes;
	__u64 writes;
	__u64 wbytes;
	__u32 pid;
	__u32 tid;
	__u8 file[PATH_MAX];
	__u8 comm[TASK_COMM_LEN];
	enum type t;
};

#define MAX_ENTRIES 10240

const volatile pid_t target_pid = 0;
GADGET_PARAM(target_pid);

// By default, only regular files are traced
const volatile bool all_files = false;
GADGET_PARAM(all_files);

static struct file_stat zero_value = {};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct file_id);
	__type(value, struct file_stat);
} stats SEC(".maps");

GADGET_TOPPER(file, stats);

static void get_file_path(struct file *file, __u8 *buf, size_t size)
{
	struct qstr dname;

	dname = BPF_CORE_READ(file, f_path.dentry, d_name);
	bpf_probe_read_kernel(buf, size, dname.name);
}

static int probe_entry(struct pt_regs *ctx, struct file *file, size_t count,
		       enum op op)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	int mode;
	struct file_id key = {};
	struct file_stat *valuep;
	u64 mntns_id;

	if (target_pid && target_pid != pid)
		return 0;

	mntns_id = gadget_get_mntns_id();

	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	mode = BPF_CORE_READ(file, f_inode, i_mode);
	if (!all_files && !S_ISREG(mode))
		return 0;

	key.dev = BPF_CORE_READ(file, f_inode, i_rdev);
	key.inode = BPF_CORE_READ(file, f_inode, i_ino);
	key.pid = pid;
	key.tid = tid;
	valuep = bpf_map_lookup_elem(&stats, &key);
	if (!valuep) {
		bpf_map_update_elem(&stats, &key, &zero_value, BPF_ANY);
		valuep = bpf_map_lookup_elem(&stats, &key);
		if (!valuep)
			return 0;
		valuep->pid = pid;
		valuep->tid = tid;
		valuep->mntns_id = mntns_id;
		bpf_get_current_comm(&valuep->comm, sizeof(valuep->comm));
		get_file_path(file, valuep->file, sizeof(valuep->file));
		if (S_ISREG(mode)) {
			valuep->t = R;
		} else if (S_ISSOCK(mode)) {
			valuep->t = S;
		} else {
			valuep->t = O;
		}
	}
	if (op == READ) {
		valuep->reads++;
		valuep->rbytes += count;
	} else { /* op == WRITE */
		valuep->writes++;
		valuep->wbytes += count;
	}
	return 0;
};

SEC("kprobe/vfs_read")
int BPF_KPROBE(ig_topfile_rd_e, struct file *file, char *buf, size_t count,
	       loff_t *pos)
{
	return probe_entry(ctx, file, count, READ);
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(ig_topfile_wr_e, struct file *file, const char *buf,
	       size_t count, loff_t *pos)
{
	return probe_entry(ctx, file, count, WRITE);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
