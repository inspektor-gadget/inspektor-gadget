/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Hengqi Chen */
/* Copyright (c) 2023-2024 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/filesystem.h>
#include <gadget/types.h>
#include <gadget/macros.h>

#include "stat.h"

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
	__u64 __pid_tgid;
};

struct file_stat {
	struct gadget_process proc;
	__u64 reads;
	gadget_bytes rbytes_raw;
	__u64 writes;
	gadget_bytes wbytes_raw;
	char file[GADGET_PATH_MAX];
	enum type t_raw;
};

#define MAX_ENTRIES 10240

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

GADGET_MAPITER(file, stats);

static void get_file_path(struct file *file, char *buf, size_t size)
{
	struct path f_path = BPF_CORE_READ(file, f_path);
	// Extract the full path string
	char *c_path = get_path_str(&f_path);
	bpf_probe_read_kernel_str(buf, GADGET_PATH_MAX, c_path);
}

static int probe_entry(struct pt_regs *ctx, struct file *file, size_t count,
		       enum op op)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	int mode;
	struct file_id key = {};
	struct file_stat *valuep;

	if (gadget_should_discard_data_current())
		return 0;

	mode = BPF_CORE_READ(file, f_inode, i_mode);
	if (!all_files && !S_ISREG(mode))
		return 0;

	key.dev = BPF_CORE_READ(file, f_inode, i_rdev);
	key.inode = BPF_CORE_READ(file, f_inode, i_ino);
	key.__pid_tgid = pid_tgid;
	valuep = bpf_map_lookup_elem(&stats, &key);
	if (!valuep) {
		bpf_map_update_elem(&stats, &key, &zero_value, BPF_ANY);
		valuep = bpf_map_lookup_elem(&stats, &key);
		if (!valuep)
			return 0;

		gadget_process_populate(&valuep->proc);
		get_file_path(file, valuep->file, sizeof(valuep->file));
		if (S_ISREG(mode)) {
			valuep->t_raw = R;
		} else if (S_ISSOCK(mode)) {
			valuep->t_raw = S;
		} else {
			valuep->t_raw = O;
		}
	}
	if (op == READ) {
		valuep->reads++;
		valuep->rbytes_raw += count;
	} else { /* op == WRITE */
		valuep->writes++;
		valuep->wbytes_raw += count;
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
