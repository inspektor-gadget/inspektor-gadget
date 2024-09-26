/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2020 Wenbo Zhang */
/* Copyright (c) 2024 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>

#define FILE_NAME_LEN 32
#define TASK_COMM_LEN 16

enum fs_file_op {
	F_READ,
	F_WRITE,
	F_OPEN,
	F_FSYNC,
	F_STATFS,
	F_MAX_OP,
};

struct event {
	gadget_timestamp timestamp_raw;
	gadget_mntns_id mntns_id;

	char comm[TASK_COMM_LEN];
	// user-space terminology for pid and tid
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 gid;

	__u64 delta_us; // TODO: use result of https://github.com/inspektor-gadget/inspektor-gadget/issues/3393
	__s64 offset;
	__u64 size; // TODO: use result of https://github.com/inspektor-gadget/inspektor-gadget/issues/3392
	enum fs_file_op op_raw;
	char file[FILE_NAME_LEN];
};

#define MAX_ENTRIES 8192

const volatile pid_t target_pid = 0;
const volatile __u64 min_lat_ms = 0;

GADGET_PARAM(target_pid);
GADGET_PARAM(min_lat_ms);

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(malloc, events, event);

struct data_key {
	__u32 tid;
	/*
	 * We need to take into account the operation to avoid losing some of
	 * them.
	 * Indeed, it is possible to enter statfs syscall while already being in
	 * an open one.
	 */
	enum fs_file_op op;
};

struct data {
	__u64 ts;
	loff_t start;
	loff_t end;
	struct dentry *dentry;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct data_key);
	__type(value, struct data);
} starts SEC(".maps");

static int probe_entry(struct dentry *dentry, enum fs_file_op op, loff_t start,
		       loff_t end)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct data data;
	struct data_key key = { .tid = tid, .op = op };
	u64 mntns_id;

	if (!dentry)
		return 0;

	if (target_pid && target_pid != pid)
		return 0;

	mntns_id = gadget_get_mntns_id();

	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	data.ts = bpf_ktime_get_ns();
	data.start = start;
	data.end = end;
	data.dentry = dentry;
	bpf_map_update_elem(&starts, &key, &data, BPF_ANY);
	return 0;
}

static int probe_exit(void *ctx, enum fs_file_op op, ssize_t size)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	__u64 end_ns, delta_ns;
	const __u8 *file_name;
	struct data *datap;
	struct event *event;
	struct data_key key = { .tid = tid, .op = op };
	struct dentry *dentry;
	u64 mntns_id;

	if (target_pid && target_pid != pid)
		return 0;

	datap = bpf_map_lookup_elem(&starts, &key);
	if (!datap)
		return 0;

	bpf_map_delete_elem(&starts, &key);

	end_ns = bpf_ktime_get_ns();
	delta_ns = end_ns - datap->ts;
	if (delta_ns <= 1000 * 1000 * min_lat_ms)
		return 0;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	event->delta_us = delta_ns / 1000;
	event->offset = datap->start;
	event->size = op != F_FSYNC ? size : datap->end - datap->start;
	event->pid = pid;
	event->tid = (__u32)pid_tgid;
	event->uid = (__u32)uid_gid;
	event->gid = (__u32)(uid_gid >> 32);
	event->op_raw = op;
	event->mntns_id = gadget_get_mntns_id();
	event->timestamp_raw = bpf_ktime_get_boot_ns();
	dentry = datap->dentry;
	file_name = BPF_CORE_READ(dentry, d_name.name);
	bpf_probe_read_kernel_str(&event->file, sizeof(event->file), file_name);
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

SEC("kprobe/dummy_file_read")
int BPF_KPROBE(ig_fssl_read_e, struct kiocb *iocb)
{
	struct dentry *dentry = BPF_CORE_READ(iocb, ki_filp, f_path.dentry);
	loff_t start = BPF_CORE_READ(iocb, ki_pos);

	return probe_entry(dentry, F_READ, start, 0);
}

SEC("kretprobe/dummy_file_read")
int BPF_KRETPROBE(ig_fssl_read_x, ssize_t ret)
{
	return probe_exit(ctx, F_READ, ret);
}

SEC("kprobe/dummy_file_write")
int BPF_KPROBE(ig_fssl_wr_e, struct kiocb *iocb)
{
	struct dentry *dentry = BPF_CORE_READ(iocb, ki_filp, f_path.dentry);
	loff_t start = BPF_CORE_READ(iocb, ki_pos);

	return probe_entry(dentry, F_WRITE, start, 0);
}

SEC("kretprobe/dummy_file_write")
int BPF_KRETPROBE(ig_fssl_wr_x, ssize_t ret)
{
	return probe_exit(ctx, F_WRITE, ret);
}

SEC("kprobe/dummy_file_open")
int BPF_KPROBE(ig_fssl_open_e, struct inode *inode, struct file *file)
{
	struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
	return probe_entry(dentry, F_OPEN, 0, 0);
}

SEC("kretprobe/dummy_file_open")
int BPF_KRETPROBE(ig_fssl_open_x)
{
	return probe_exit(ctx, F_OPEN, 0);
}

SEC("kprobe/dummy_file_sync")
int BPF_KPROBE(ig_fssl_sync_e, struct file *file, loff_t start, loff_t end)
{
	struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
	return probe_entry(dentry, F_FSYNC, start, end);
}

SEC("kretprobe/dummy_file_sync")
int BPF_KRETPROBE(ig_fssl_sync_x)
{
	return probe_exit(ctx, F_FSYNC, 0);
}

SEC("kprobe/dummy_file_statfs")
int BPF_KPROBE(ig_fssl_statfs_e, struct dentry *dentry, struct kstatfs *buf)
{
	return probe_entry(dentry, F_STATFS, 0, 0);
}

SEC("kretprobe/dummy_file_statfs")
int BPF_KRETPROBE(ig_fssl_statfs_x)
{
	return probe_exit(ctx, F_STATFS, 0);
}

// Comment out the fentry/fexit functions as we don't support them yet.
//SEC("fentry/dummy_file_read")
//int BPF_PROG(file_read_fentry, struct kiocb *iocb)
//{
//	struct file *fp = iocb->ki_filp;
//	loff_t start = iocb->ki_pos;
//
//	return probe_entry(fp, start, 0);
//}
//
//SEC("fexit/dummy_file_read")
//int BPF_PROG(file_read_fexit, struct kiocb *iocb, struct iov_iter *to, ssize_t ret)
//{
//	return probe_exit(ctx, READ, ret);
//}
//
//SEC("fentry/dummy_file_write")
//int BPF_PROG(file_write_fentry, struct kiocb *iocb)
//{
//	struct file *fp = iocb->ki_filp;
//	loff_t start = iocb->ki_pos;
//
//	return probe_entry(fp, start, 0);
//}
//
//SEC("fexit/dummy_file_write")
//int BPF_PROG(file_write_fexit, struct kiocb *iocb, struct iov_iter *from, ssize_t ret)
//{
//	return probe_exit(ctx, WRITE, ret);
//}
//
//SEC("fentry/dummy_file_open")
//int BPF_PROG(file_open_fentry, struct inode *inode, struct file *file)
//{
//	return probe_entry(file, 0, 0);
//}
//
//SEC("fexit/dummy_file_open")
//int BPF_PROG(file_open_fexit)
//{
//	return probe_exit(ctx, OPEN, 0);
//}
//
//SEC("fentry/dummy_file_sync")
//int BPF_PROG(file_sync_fentry, struct file *file, loff_t start, loff_t end)
//{
//	return probe_entry(file, start, end);
//}
//
//SEC("fexit/dummy_file_sync")
//int BPF_PROG(file_sync_fexit)
//{
//	return probe_exit(ctx, FSYNC, 0);
//}

char LICENSE[] SEC("license") = "GPL";
