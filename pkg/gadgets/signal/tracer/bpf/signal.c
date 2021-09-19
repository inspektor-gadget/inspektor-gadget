// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 The Inspektor Gadget authors */

#include <vmlinux/vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#ifndef SIGILL
#define SIGILL 4
#endif
#ifndef SIGUSR1
#define SIGUSR1 10
#endif

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

SEC("tracepoint/sys_enter_close")
int tracepoint__sys_enter_close(struct trace_event_raw_sys_enter *ctx)
{
	struct task_struct *task = (struct task_struct *) bpf_get_current_task();
	int nr_threads = BPF_CORE_READ(task, signal, nr_threads);
	if (nr_threads < 2)
		return 0;

	char comm[TASK_COMM_LEN];
	bpf_get_current_comm(comm, sizeof(comm));
	int is_target = comm[0] == 'g' && comm[1] == 'o' && comm[2] == 's' && comm[3] == 'i';

	if (!is_target)
		return 0;

	bpf_printk("close called: [%s] (bool=%d fd=%d)", comm, is_target, (int)ctx->args[0]);

	bpf_send_signal(SIGILL);
	return 0;
}

char _license[] SEC("license") = "GPL";
