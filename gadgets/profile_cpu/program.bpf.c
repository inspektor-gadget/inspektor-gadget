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

/* The aggregation key holds only the sample's *identity*: the user stack is
 * represented by its stack id (a stable hash of the stack), not by the whole
 * struct gadget_user_stack. Embedding the full struct here would be wrong
 * because it carries per-sample fields (boot_timestamp, otel_correlation_id)
 * that differ on every sample, which would make every sample a unique key and
 * defeat aggregation. The full struct is stored in the value instead (see
 * struct values below), mirroring profile_cuda.
 */
struct key_t {
	__u64 kernel_ip;
	__u32 user_stack_id;
	gadget_kernel_stack kern_stack_raw;
	struct gadget_process proc;
};

/* Per-CPU temporary storage for struct key_t. Using a per-CPU array
 * instead of a stack-local variable reduces the BPF stack frame size
 * by sizeof(struct key_t) (~148 bytes). See the comment in
 * profile_cuda/program.bpf.c for details on the 256-byte verifier
 * limit with tail calls.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct key_t);
} tmp_key SEC(".maps");

static const struct key_t empty_key;

const volatile bool kernel_stacks_only = false;
GADGET_PARAM(kernel_stacks_only);

const volatile bool user_stacks_only = false;
GADGET_PARAM(user_stacks_only);

const volatile bool include_idle = false;
GADGET_PARAM(include_idle);

/* The value carries the aggregated sample count plus the full user-stack
 * metadata. user_stack_raw lives here (not in the key) so that identical
 * stacks aggregate: its per-sample fields (boot_timestamp, otel_correlation_id)
 * would otherwise make every sample a unique key. On first insertion the
 * metadata of that first sample is stored; subsequent identical stacks only
 * bump samples. This mirrors profile_cuda's alloc_val.
 */
struct values {
	__u64 samples;
	struct gadget_user_stack user_stack_raw;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct key_t);
	__type(value, struct values);
	__uint(max_entries, MAX_ENTRIES);
} counts SEC(".maps");

GADGET_MAPITER(samples, counts);

/* Per-CPU temporary storage for the user stack and the value struct, to keep
 * them off the BPF stack (same rationale as tmp_key above).
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct gadget_user_stack);
} tmp_gadget_user_stack SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct values);
} tmp_values SEC(".maps");

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
	u32 map_key = 0;
	bpf_map_update_elem(&tmp_key, &map_key, &empty_key, BPF_ANY);
	struct key_t *key = bpf_map_lookup_elem(&tmp_key, &map_key);
	if (!key)
		return 0;

	if (!include_idle && tid == 0)
		return 0;

	gadget_process_populate(&key->proc);

	if (user_stacks_only)
		key->kern_stack_raw = -1;
	else
		key->kern_stack_raw =
			bpf_get_stackid(&ctx->regs, &ig_kstack, 0);

	/* Fetch the user stack into per-CPU scratch and key only on its stack
	 * id, keeping the full metadata (with its per-sample fields) out of the
	 * aggregation key. See the comments on struct key_t / struct values.
	 */
	struct gadget_user_stack *ustack_raw =
		bpf_map_lookup_elem(&tmp_gadget_user_stack, &map_key);
	if (!ustack_raw)
		return 0;
	if (!kernel_stacks_only)
		gadget_get_user_stack(ctx, ustack_raw);
	else
		__builtin_memset(ustack_raw, 0, sizeof(*ustack_raw));
	key->user_stack_id = ustack_raw->stack_id;

	if (key->kern_stack_raw >= 0) {
		// populate extras to fix the kernel stack
		u64 ip = PT_REGS_IP(&ctx->regs);

		if (is_kernel_addr(ip))
			key->kernel_ip = ip;
	}

	valp = bpf_map_lookup_elem(&counts, key);
	if (!valp) {
		struct values *new_val =
			bpf_map_lookup_elem(&tmp_values, &map_key);
		if (!new_val)
			return 0;
		new_val->samples = 1;
		new_val->user_stack_raw = *ustack_raw;
		bpf_map_update_elem(&counts, key, new_val, BPF_NOEXIST);
	} else {
		__sync_fetch_and_add(&valp->samples, 1);
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
