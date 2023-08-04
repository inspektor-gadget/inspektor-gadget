// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook, (c) 2022 The Inspektor Gadget authors */
#include <vmlinux/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "pid_iter.h"

const volatile __u64 bpf_prog_fops_addr = 0;

struct pid_iter_entry *unused __attribute__((unused));

SEC("iter/task_file")
int ig_top_ebpf_it(struct bpf_iter__task_file *ctx)
{
	struct file *file = ctx->file;
	struct task_struct *task = ctx->task;
	struct pid_iter_entry e;

	if (!file || !task)
		return 0;

	// We need to have an address of bpf_prog_fops to run
	// TODO: Currently cilium/ebpf doesn't support .ksyms, this is why we get the info from userspace right now
	if (bpf_prog_fops_addr == 0 ||
	    (__u64)(file->f_op) != bpf_prog_fops_addr)
		return 0;

	__builtin_memset(&e, 0, sizeof(e));
	e.pid = task->tgid;
	e.id = BPF_CORE_READ((struct bpf_prog *)(file->private_data), aux, id);

	bpf_probe_read_kernel_str(&e.comm, sizeof(e.comm),
				  task->group_leader->comm);
	bpf_seq_write(ctx->meta->seq, &e, sizeof(e));

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
