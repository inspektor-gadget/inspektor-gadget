// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note

/* Copyright (c) 2021 The Inspektor Gadget authors */

/* Inspired by the BPF iterator in the Linux tree:
 * https://github.com/torvalds/linux/blob/v5.12/tools/testing/selftests/bpf/progs/bpf_iter_task.c
 */

/* This BPF program uses the GPL-restricted function bpf_seq_printf().
 */

#include <vmlinux/vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "mntns_filter.h"
#include "types.h"

typedef u64 field_placeholder_btf;

struct myevent {
	__u32 tgid;
	__u32 pid;
	__u32 parent_pid;
	__u32 uid;
	__u32 gid;

	field_placeholder_btf user;
	field_placeholder_btf user_ns;

	mnt_ns_id_t mntns_id;
	__u8 comm[TASK_COMM_LEN];
};


const volatile bool show_threads = false;

// Describes the type produced the by iterator program. It's only used to get the BTF information of
// such type.
const struct myevent *GADGET_ITER_TYPE_VAR_NAME __attribute__((unused));

SEC("iter/task")
int ig_snap_proc(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct task_struct *parent;
	pid_t parent_pid;
	struct btf_ptr ptr = {};
	char nul = '\0';

	struct myevent event = {};

	if (task == NULL)
		return 0;

	if (!show_threads && task->tgid != task->pid)
		return 0;

	__u64 mntns_id = task->nsproxy->mnt_ns->ns.inum;

	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	parent = task->real_parent;
	if (!parent)
		parent_pid = -1;
	else
		parent_pid = parent->pid;

	__u32 uid = task->cred->uid.val;
	__u32 gid = task->cred->gid.val;

	event.tgid = task->tgid;
	event.pid = task->pid;
	event.parent_pid = parent_pid;
	event.mntns_id = mntns_id;
	event.uid = uid;
	event.gid = gid;
	__builtin_memcpy(event.comm, task->comm, TASK_COMM_LEN);

	bpf_seq_write(seq, &event, sizeof(event));

	ptr.type_id = bpf_core_type_id_kernel(struct user_struct);
	ptr.ptr = BPF_CORE_READ(task, cred, user);
	bpf_seq_printf_btf(seq, &ptr, sizeof(ptr), 0);
	bpf_seq_write(seq, &nul, 1);

	ptr.type_id = bpf_core_type_id_kernel(struct user_namespace);
	ptr.ptr = BPF_CORE_READ(task, cred, user_ns);
	bpf_seq_printf_btf(seq, &ptr, sizeof(ptr), 0);
	bpf_seq_write(seq, &nul, 1);


	return 0;
}

char _license[] SEC("license") = "GPL";
