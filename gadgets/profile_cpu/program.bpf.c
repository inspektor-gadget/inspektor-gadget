/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2022 LG Electronics */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <gadget/maps.bpf.h>
#include <gadget/mntns_filter.h>
#include <gadget/filter.h>
#include <gadget/types.h>
#include <gadget/macros.h>
#include <gadget/common.h>
#include <gadget/kernel_stack_map.h>
#include <gadget/user_stack_map.h>

#define MAX_ENTRIES 10240

struct key_t {
	__u64 kernel_ip;
	struct gadget_user_stack user_stack_raw;
	gadget_kernel_stack kern_stack_raw;
	struct gadget_process proc;
};

const volatile bool kernel_stacks_only = false;
GADGET_PARAM(kernel_stacks_only);

const volatile bool user_stacks_only = false;
GADGET_PARAM(user_stacks_only);

const volatile bool include_idle = false;
GADGET_PARAM(include_idle);

struct values {
	__u64 samples;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct key_t);
	__type(value, struct values);
	__uint(max_entries, MAX_ENTRIES);
} counts SEC(".maps");

GADGET_MAPITER(samples, counts);

/*
 * If PAGE_OFFSET macro is not available in vmlinux.h, determine ip whose MSB
 * (Most Significant Bit) is 1 as the kernel address.
 * TODO: use end address of user space to determine the address space of ip
 */
#if defined(__TARGET_ARCH_arm64) || defined(__TARGET_ARCH_x86)
#define BITS_PER_ADDR (64)
#define MSB_SET_ULONG (1UL << (BITS_PER_ADDR - 1))
static __always_inline bool is_kernel_addr(u64 addr)
{
	return !!(addr & MSB_SET_ULONG);
}
#else
static __always_inline bool is_kernel_addr(u64 addr)
{
	return false;
}
#endif /* __TARGET_ARCH_arm64 || __TARGET_ARCH_x86 */

SEC("perf_event/profiler")
int ig_prof_cpu(struct bpf_perf_event_data *ctx)
{
	if (gadget_should_discard_data_current())
		return 0;

	u64 id = bpf_get_current_pid_tgid();

	u32 tid = id;
	struct values *valp;
	static const struct values zero = {
		0,
	};
	struct key_t key = {};

	if (!include_idle && tid == 0)
		return 0;

	gadget_process_populate(&key.proc);

	if (user_stacks_only)
		key.kern_stack_raw = -1;
	else
		key.kern_stack_raw = bpf_get_stackid(&ctx->regs, &ig_kstack, 0);

	if (!kernel_stacks_only)
		gadget_get_user_stack(ctx, &key.user_stack_raw);

	if (key.kern_stack_raw >= 0) {
		// populate extras to fix the kernel stack
		u64 ip = PT_REGS_IP(&ctx->regs);

		if (is_kernel_addr(ip))
			key.kernel_ip = ip;
	}

	valp = bpf_map_lookup_or_try_init(&counts, &key, &zero);
	if (valp)
		__sync_fetch_and_add(&valp->samples, 1);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
