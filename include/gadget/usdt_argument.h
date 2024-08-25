// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 The Inspektor Gadget authors

#ifndef __USDT_ARGUMENT_H
#define __USDT_ARGUMENT_H

/* Since eBPF global functions cannot return pointers, we use a per-cpu array to store the argument value. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 1);
} __usdt_args_buffer SEC(".maps");

/* Sync with pkg/uprobetracer/bpf/usdt_helper.bpf.c */
/* Returns true if the argument value is stored in the above map successfully, otherwise returns false */
/* Placeholder only here, needs to be replaced by bpf extension using BPF_F_REPLACE */
__attribute__((optnone)) bool __usdt_get_argument(struct pt_regs *ctx,
						  u64 arg_idx)
{
	return !ctx;
}

/* Returns NULL on failure, otherwise returns an u64* pointing to the global buffer in map */
/* The buffer will be reused, so users need to store the value before next call */
static __always_inline u64 *usdt_get_argument(struct pt_regs *ctx, u64 arg_idx)
{
	u32 zero = 0;

	if (!__usdt_get_argument(ctx, arg_idx))
		return NULL;

	return bpf_map_lookup_elem(&__usdt_args_buffer, &zero);
}

#endif /* __USDT_ARGUMENT_H */
