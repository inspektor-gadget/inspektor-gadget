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

/* Pinned gpu-ebpf-bridge maps + CO-RE helpers, shared with the other GPU
 * gadgets. Only pulled in for the optional --gpu-idle-only filter below;
 * when that filter is off the maps are declared but never read, so on a
 * host without the bridge they are simply created empty and ignored.
 */
#define GPU_BRIDGE_WANT_PER_PID
#define GPU_BRIDGE_WANT_DEVICE
#define GPU_BRIDGE_WANT_META
#include <gadget/gpu_bridge_maps.h>

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

/* ---- GPU-idle attribution (optional) ----
 *
 * With --gpu-idle-only, a sample is only recorded when the sampled process
 * currently owns GPU memory AND its GPU is underutilized at that instant.
 * The result is a flamegraph of exactly the CPU code that runs while the
 * GPU the process paid for sits idle: the on-CPU work standing between
 * successive GPU kernels (GPU starvation). Unlike the recency-based
 * trace_gpu_starvation, a sampler has no dependence on the bridge poll
 * interval, so it also surfaces "many small gaps" starvation (e.g. a
 * per-frame CPU preprocess step that keeps the GPU at ~50% duty cycle).
 *
 * Data comes from the gpu-ebpf-bridge pinned maps; if the bridge is not
 * running these maps are empty, gpu_meta_fresh() fails, and every sample is
 * discarded (empty profile) rather than mis-attributed.
 */
const volatile bool gpu_idle_only = false;
GADGET_PARAM(gpu_idle_only);

/* Record a sample only if the primary GPU's SM utilization is strictly below
 * this percentage. Utilization at or above it means the GPU is busy, so the
 * concurrent CPU work is not starving it.
 */
const volatile __u32 gpu_util_max_pct = 70;
GADGET_PARAM(gpu_util_max_pct);

/* Minimum resident GPU memory (bytes) for a process to count as a GPU
 * holder. The default of 1 means "any GPU allocation at all".
 */
const volatile __u64 min_gpu_mem_bytes = 1;
GADGET_PARAM(min_gpu_mem_bytes);

/* Bridge data older than this (milliseconds) is treated as stale and the
 * sample is discarded, so a dead/paused bridge never yields stale
 * attribution.
 */
const volatile __u64 stale_threshold_ms = 300;
GADGET_PARAM(stale_threshold_ms);

/* The value carries the aggregated sample count plus the full user-stack
 * metadata. user_stack_raw lives here (not in the key) so that identical
 * stacks aggregate: its per-sample fields (boot_timestamp,
 * otel_correlation_id) would otherwise make every sample a unique key. On
 * first insertion the metadata of that first sample is stored; subsequent
 * identical stacks only bump samples. This mirrors profile_cuda's alloc_val.
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

/* Returns true if the sample should be discarded because --gpu-idle-only is
 * on and the current process is not a GPU holder whose GPU is currently idle.
 * When gpu_idle_only is off this is compiled to a constant false and the
 * bridge maps are never touched.
 */
static __always_inline bool gpu_idle_gate_discards(__u32 tgid)
{
	if (!gpu_idle_only)
		return false;

	__u64 now = bpf_ktime_get_boot_ns();
	if (!gpu_meta_fresh(now, stale_threshold_ms))
		return true;

	struct gpu_pid_metrics_aggregated *gm =
		gpu_pid_holder(tgid, min_gpu_mem_bytes);
	if (!gm)
		return true;

	/* Single-GPU process: gate on that device's utilization. Multi-device
	 * holders (gpu_device_primary == GPU_DEVICE_PRIMARY_MULTI) have no
	 * single primary to consult, so require ownership only and skip the
	 * per-device utilization gate.
	 */
	if (gm->gpu_device_primary != GPU_DEVICE_PRIMARY_MULTI &&
	    !gpu_device_underutilized(gm->gpu_device_primary, gpu_util_max_pct))
		return true;

	return false;
}

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

	if (gpu_idle_gate_discards(id >> 32))
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
