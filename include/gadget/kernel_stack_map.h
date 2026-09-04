// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 The Inspektor Gadget authors

#ifndef __STACK_MAP_H
#define __STACK_MAP_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include <gadget/macros.h>

#define GADGET_KERNEL_MAX_STACK_DEPTH 127
#define GADGET_KERNEL_STACK_MAP_MAX_ENTRIES 10000

/* A consumer whose stack collection is runtime-optional can define this to
 * the parameter expression that guards every gadget_get_kernel_stack() call.
 */
#ifdef GADGET_KERNEL_STACK_MAP_ONLY_IF_EXPR
#define __GADGET_KERNEL_STACK_MAP_ONLY_IF \
	GADGET_MAP_ONLY_IF(GADGET_KERNEL_STACK_MAP_ONLY_IF_EXPR)
#else
#define __GADGET_KERNEL_STACK_MAP_ONLY_IF
#endif

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, GADGET_KERNEL_MAX_STACK_DEPTH * sizeof(u64));
	__uint(max_entries, GADGET_KERNEL_STACK_MAP_MAX_ENTRIES);
} ig_kstack SEC(".maps") __GADGET_KERNEL_STACK_MAP_ONLY_IF;

/* Returns the kernel stack id, positive or zero on success, negative on failure */
static __always_inline long gadget_get_kernel_stack(void *ctx)
{
	return bpf_get_stackid(ctx, &ig_kstack, BPF_F_FAST_STACK_CMP);
}

#undef __GADGET_KERNEL_STACK_MAP_ONLY_IF

#endif /* __STACK_MAP_H */
