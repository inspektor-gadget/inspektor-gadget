// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 The Inspektor Gadget authors

#ifndef __STACK_MAP_H
#define __STACK_MAP_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include <gadget/types.h>

#define GADGET_KERNEL_MAX_STACK_DEPTH 127
#define GADGET_KERNEL_STACK_MAP_MAX_ENTRIES 10000

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, GADGET_KERNEL_MAX_STACK_DEPTH * sizeof(u64));
	__uint(max_entries, GADGET_KERNEL_STACK_MAP_MAX_ENTRIES);
} ig_kstack SEC(".maps");

/* Sentinel for a gadget_kernel_stack field that holds no stack because the
 * gadget did not collect one, e.g. when its collect_kstack parameter is off.
 *
 * gadget_kernel_stack is unsigned, and zero is a perfectly valid stack id
 * returned by bpf_get_stackid(), so there is no natural "no stack" value.
 * Without this sentinel, a field left at zero makes userspace look up stack
 * id 0 and log "stack with ID 0 is lost" for every event.
 *
 * Gadgets that collect the kernel stack conditionally must set this in the
 * branch where they do not: a ring buffer reservation is not guaranteed to be
 * zero-filled, so leaving the field untouched yields a recycled stack id from
 * an earlier event, which userspace resolves to a plausible but wrong stack.
 *
 * -1 is safe to use even though a failing bpf_get_stackid() also stores a
 * negative errno in this field. It returns -EINVAL, -EFAULT, -EEXIST or
 * -ENOMEM (see BPF_CALL_3(bpf_get_stackid) in kernel/bpf/stackmap.c) but never
 * -EPERM, so -1 is unambiguous. Userspace therefore tests for this sentinel
 * before decoding the value as an errno.
 */
#define GADGET_KERNEL_STACK_ID_NONE ((gadget_kernel_stack)-1)

/* Returns the kernel stack id, positive or zero on success, negative on
 * failure. The negative errno is deliberately passed on rather than folded
 * into GADGET_KERNEL_STACK_ID_NONE, so that userspace can tell a genuine
 * failure (e.g. -ENOMEM when ig_kstack is full) from a stack that was never
 * collected, and report it.
 */
static __always_inline long gadget_get_kernel_stack(void *ctx)
{
	return bpf_get_stackid(ctx, &ig_kstack, BPF_F_FAST_STACK_CMP);
}

#endif /* __STACK_MAP_H */
