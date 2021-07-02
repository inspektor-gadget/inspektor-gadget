// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 The Inspektor Gadget authors */

/* Inspired by the BPF iterator in the Linux tree:
 * https://github.com/torvalds/linux/blob/v5.12/tools/testing/selftests/bpf/progs/bpf_iter_task.c
 */

/* This BPF program uses the GPL-restricted function bpf_seq_printf().
 */

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

/* libbpf v0.4.0 introduced BPF_SEQ_PRINTF in bpf_tracing.h.
 * In future versions, it will be in bpf_helpers.h.
 */
#include <bpf/bpf_tracing.h>

#include "../../../../pkg/gadgettracermanager/bpf-maps.h"

struct bpf_iter_meta {
	__bpf_md_ptr(struct seq_file *, seq);
	__u64 session_id;
	__u64 seq_num;
};

struct bpf_iter__task {
	struct bpf_iter_meta *meta;
	struct task_struct *task;
} __attribute__((preserve_access_index));

struct nsproxy {
	struct mnt_namespace *mnt_ns;
} __attribute__((preserve_access_index));

struct task_struct {
	int pid;
	int tgid;
	char comm[16];
	struct nsproxy *nsproxy;
} __attribute__((preserve_access_index));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u64);
	__uint(max_entries, 128);
} context SEC(".maps");

SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	__u32 seq_num = ctx->meta->seq_num;
	__u64 session_id = ctx->meta->session_id;
	struct task_struct *task = ctx->task;
	__u64 *counter;
	__u64 zero = 0;

	if (seq_num == 0) {
		BPF_SEQ_PRINTF(seq, "[\n");
		bpf_map_update_elem(&context, &session_id, &zero, BPF_ANY);
	}

	counter = bpf_map_lookup_elem(&context, &session_id);
	if (!counter)
		return 0;

	if (task == (void *)0) {
		if (*counter)
			BPF_SEQ_PRINTF(seq, "\n");
		BPF_SEQ_PRINTF(seq, "]\n");
		bpf_map_delete_elem(&context, &session_id);
		return 0;
	}

	__u64 mntns_id = task->nsproxy->mnt_ns->ns.inum;

#ifdef WITH_FILTER
	__u32 *found = bpf_map_lookup_elem(&filter, &mntns_id);
	if (!found)
		return 0;
#endif

	if (*counter)
		BPF_SEQ_PRINTF(seq, ",\n");

	__sync_fetch_and_add(counter, 1);
	BPF_SEQ_PRINTF(seq, "  {\n    \"tgid\": %d,\n    \"pid\": %d,\n    \"comm\": \"%s\",\n    \"mntns\": %llu", task->tgid, task->pid, task->comm, mntns_id);

	struct container *container_entry;
	container_entry = bpf_map_lookup_elem(&containers, &mntns_id);
	if (container_entry) {
		BPF_SEQ_PRINTF(seq, ",\n    \"container_id\": \"%s\"", container_entry->container_id);
		BPF_SEQ_PRINTF(seq, ",\n    \"kubernetes_namespace\": \"%s\"", container_entry->kubernetes_namespace);
		BPF_SEQ_PRINTF(seq, ",\n    \"kubernetes_pod\": \"%s\"", container_entry->kubernetes_pod);
		BPF_SEQ_PRINTF(seq, ",\n    \"kubernetes_container\": \"%s\"", container_entry->kubernetes_container);
	}

	BPF_SEQ_PRINTF(seq, "\n  }");

	return 0;
}

char _license[] SEC("license") = "GPL";
