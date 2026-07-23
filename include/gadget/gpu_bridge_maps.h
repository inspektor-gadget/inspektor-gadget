/* SPDX-License-Identifier: Apache-2.0 */

/*
 * gpu_bridge_maps.h - shared BPF map declarations for gpu-ebpf-bridge
 * consumers.
 *
 * The gpu-ebpf-bridge daemon pins four BPF maps under /sys/fs/bpf/ (see
 * <gadget/gpu_types.h> for the struct layouts). Both the bridge's own
 * map-defining object (pkg/gpu-ebpf-bridge/maps/bpf/gpu_types.bpf.c) and
 * consumer gadgets (gpu_top, gpu_top_per_pid, trace_gpu_starvation,
 * profile_cpu) need identical `LIBBPF_PIN_BY_NAME` declarations. This
 * header is the single source of truth for those declarations so they
 * are not copy-pasted (and cannot drift) across consumers.
 *
 * Usage: a consumer selects only the maps it actually uses, so it does
 * not create/pin maps it does not need. Define one or more of the
 * following macros BEFORE including this header:
 *
 *   GPU_BRIDGE_WANT_META
 *   GPU_BRIDGE_WANT_DEVICE
 *   GPU_BRIDGE_WANT_PER_PID
 *   GPU_BRIDGE_WANT_PER_PID_PER_DEVICE
 *   GPU_BRIDGE_WANT_ALL   -- selects all four (used by the bridge itself)
 *
 * This header must be included after <vmlinux.h> and <bpf/bpf_helpers.h>
 * (for the map macros and bpf_map_lookup_elem used by the helpers below).
 */

#ifndef __GPU_BRIDGE_MAPS_H
#define __GPU_BRIDGE_MAPS_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include <gadget/gpu_types.h>

#ifdef GPU_BRIDGE_WANT_ALL
#define GPU_BRIDGE_WANT_META
#define GPU_BRIDGE_WANT_DEVICE
#define GPU_BRIDGE_WANT_PER_PID
#define GPU_BRIDGE_WANT_PER_PID_PER_DEVICE
#endif

/* ---- map declarations ---- */

#ifdef GPU_BRIDGE_WANT_META
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct gpu_meta);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} gpu_meta SEC(".maps");
#endif

#ifdef GPU_BRIDGE_WANT_DEVICE
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, GPU_MAX_DEVICES);
	__type(key, __u32);
	__type(value, struct gpu_device_metrics);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} gpu_device SEC(".maps");
#endif

#ifdef GPU_BRIDGE_WANT_PER_PID
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32); /* host tgid */
	__type(value, struct gpu_pid_metrics_aggregated);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} gpu_per_pid SEC(".maps");
#endif

#ifdef GPU_BRIDGE_WANT_PER_PID_PER_DEVICE
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64); /* (pid << 32) | device_idx */
	__type(value, struct gpu_pid_metrics);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} gpu_per_pid_per_device SEC(".maps");
#endif

/* ---- CO-RE read helpers ----
 *
 * Each helper is defined only when the map it reads was selected, so an
 * unused map is neither declared nor referenced. Helpers are
 * __always_inline; an unused one is dropped by the compiler.
 */

#ifdef GPU_BRIDGE_WANT_META
/* Returns the gpu_meta record if the bridge data is fresh (last tick within
 * stale_threshold_ms of now_boot_ns), else NULL. now_boot_ns must be a
 * CLOCK_BOOTTIME timestamp (e.g. bpf_ktime_get_boot_ns()). Returning the
 * record (not just a bool) lets callers also read clock_offset_ns. */
static __always_inline struct gpu_meta *gpu_meta_fresh(__u64 now_boot_ns,
						       __u64 stale_threshold_ms)
{
	__u32 zero = 0;
	struct gpu_meta *meta = bpf_map_lookup_elem(&gpu_meta, &zero);
	if (!meta)
		return NULL;
	if ((now_boot_ns - meta->last_update_boottime_ns) >
	    stale_threshold_ms * 1000000ULL)
		return NULL;
	return meta;
}
#endif

#ifdef GPU_BRIDGE_WANT_PER_PID
/* Returns the aggregated per-PID record if tgid currently holds at least
 * min_gpu_mem_bytes of GPU memory, else NULL. */
static __always_inline struct gpu_pid_metrics_aggregated *
gpu_pid_holder(__u32 tgid, __u64 min_gpu_mem_bytes)
{
	struct gpu_pid_metrics_aggregated *gm =
		bpf_map_lookup_elem(&gpu_per_pid, &tgid);
	if (!gm || gm->used_gpu_memory_total < min_gpu_mem_bytes)
		return NULL;
	return gm;
}
#endif

#ifdef GPU_BRIDGE_WANT_DEVICE
/* Returns true if device dev_idx exists and its SM utilization is strictly
 * below max_pct. An unknown device returns false (we cannot claim it is
 * underutilized), so callers gating on "GPU idle" fail safe. */
static __always_inline bool gpu_device_underutilized(__u8 dev_idx,
						     __u32 max_pct)
{
	__u32 key = dev_idx;
	struct gpu_device_metrics *d = bpf_map_lookup_elem(&gpu_device, &key);
	if (!d)
		return false;
	return d->sm_util_pct < max_pct;
}
#endif

#endif /* __GPU_BRIDGE_MAPS_H */
