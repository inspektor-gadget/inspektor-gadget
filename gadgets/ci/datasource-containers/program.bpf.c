/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 The Inspektor Gadget authors */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/macros.h>
#include <gadget/types.h>

#define NAME_MAX 255

struct event {
	struct gadget_process proc;
};

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(open, events, event);

SEC("tracepoint/syscalls/sys_enter_openat")
int enter_openat(struct syscall_trace_enter *ctx)
{
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
