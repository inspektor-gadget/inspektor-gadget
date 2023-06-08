// SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0

/* Copyright (c) 2023 The Inspektor Gadget authors */

/*
 * This BPF program uses the GPL-restricted function bpf_seq_printf().
 */

#include <vmlinux/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "mntns_filter.h"

char _license[] SEC("license") = "GPL";

const volatile __u64 socket_file_ops_addr = 0;
const volatile __u64 bpf_map_fops_addr = 0;
const volatile __u64 bpf_prog_fops_addr = 0;
const volatile __u64 bpf_link_fops_addr = 0;
const volatile __u64 eventpoll_fops_addr = 0;
const volatile __u64 pipe_inode_info_addr = 0;
const volatile __u64 tty_fops_addr = 0;

// This iterates on all the open files (from all processes).
SEC("iter/task_file")
int ig_file_it(struct bpf_iter__task_file *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct file *file = ctx->file;
	struct task_struct *task = ctx->task;
	struct task_struct *parent;
	pid_t parent_pid;
	u64 mntns_id;
	struct btf_ptr ptr = {};

	if (!file || !task)
		return 0;

	mntns_id = (u64) BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	__u64 f_op = (__u64)(file->f_op);

	parent = task->real_parent;
	if (!parent)
		parent_pid = -1;
	else
		parent_pid = parent->pid;

	ptr.ptr = BPF_CORE_READ(file, private_data);

	if (f_op == socket_file_ops_addr) {
		ptr.type_id = bpf_core_type_id_kernel(struct socket);
	} else if(f_op == bpf_map_fops_addr) {
		ptr.type_id = bpf_core_type_id_kernel(struct bpf_map);
	} else if(f_op == bpf_prog_fops_addr) {
		ptr.type_id = bpf_core_type_id_kernel(struct bpf_prog);
	} else if(f_op == bpf_link_fops_addr) {
		ptr.type_id = bpf_core_type_id_kernel(struct bpf_link);
	} else if (f_op == eventpoll_fops_addr) {
		ptr.type_id = bpf_core_type_id_kernel(struct eventpoll);
	} else if (f_op == tty_fops_addr) {
		ptr.type_id = bpf_core_type_id_kernel(struct tty_struct);
	} else {
		goto skip_btf;
    }

	bpf_seq_printf_btf(seq, &ptr, sizeof(ptr), 0);

skip_btf:
	BPF_SEQ_PRINTF(seq, "#### %llu ", mntns_id);

	BPF_SEQ_PRINTF(seq, "%d %d %u %u ",
		parent_pid, task->tgid,
		task->cred->uid.val,
		task->cred->gid.val);
	BPF_SEQ_PRINTF(seq, "%d %lu %llu ",
		ctx->fd,
		file->f_inode->i_ino,
		f_op);
	BPF_SEQ_PRINTF(seq, "%s\n",
		task->comm);

	return 0;
}
