// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note

/* Copyright (c) 2021 The Inspektor Gadget authors */

/* Inspired by the BPF iterator in the Linux tree:
 * https://github.com/torvalds/linux/blob/v5.12/tools/testing/selftests/bpf/progs/bpf_iter_task.c
 */

/* This BPF program uses the GPL-restricted function bpf_seq_printf().
 */

#include <vmlinux/vmlinux.h>

#include <bpf/bpf_helpers.h>
/* libbpf v0.4.0 introduced BPF_SEQ_PRINTF in bpf_tracing.h.
 * In future versions, it will be in bpf_helpers.h.
 */
#include <bpf/bpf_tracing.h>

#include <gadgettracermanager/bpf-maps.h>

SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	__u32 seq_num = ctx->meta->seq_num;
	__u64 session_id = ctx->meta->session_id;
	struct task_struct *task = ctx->task;

	if (task == NULL) {
		return 0;
	}

	__u64 mntns_id = task->nsproxy->mnt_ns->ns.inum;

#ifdef WITH_FILTER
	__u32 *found = bpf_map_lookup_elem(&filter, &mntns_id);
	if (!found)
		return 0;
#endif

	BPF_SEQ_PRINTF(seq, "%d %d %s %llu\n", task->tgid, task->pid, task->comm, mntns_id);

	return 0;
}

char _license[] SEC("license") = "GPL";
