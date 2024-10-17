// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note

/* Copyright (c) 2021 The Inspektor Gadget authors */

/* Inspired by the BPF iterator in the Linux tree:
 * https://github.com/torvalds/linux/blob/v5.12/tools/testing/selftests/bpf/progs/bpf_iter_task.c
 */

/* This BPF program uses the GPL-restricted function bpf_seq_write(). */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

const volatile bool show_threads = false;

GADGET_PARAM(show_threads);

GADGET_SNAPSHOTTER(processes, gadget_process, ig_snap_proc);

SEC("iter/task")
int ig_snap_proc(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct task_struct *parent;

	struct gadget_process process = {};

	if (task == NULL)
		return 0;

	if (!show_threads && task->tgid != task->pid)
		return 0;

	__u64 mntns_id = task->nsproxy->mnt_ns->ns.inum;

	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	process.mntns_id = mntns_id;
	__builtin_memcpy(process.comm, task->comm, TASK_COMM_LEN);
	process.pid = task->tgid;
	process.tid = task->pid;
	process.creds.uid = task->cred->uid.val;
	process.creds.gid = task->cred->gid.val;

	parent = task->real_parent;
	if (parent) {
		process.parent.pid = parent->pid;
		__builtin_memcpy(process.parent.comm, parent->comm,
				 TASK_COMM_LEN);
	}

	bpf_seq_write(seq, &process, sizeof(process));

	return 0;
}

char _license[] SEC("license") = "GPL";
