/* SPDX-License-Identifier: Apache-2.0 */

/*
 * gpu_types.h - public API contract for the gpu-ebpf-bridge BPF maps.
 *
 * The gpu-ebpf-bridge daemon (cmd/gpu-ebpf-bridge) pins four BPF maps
 * under /sys/fs/bpf/:
 *
 *   gpu_meta                   -- ARRAY[1]    -> struct gpu_meta
 *   gpu_device                 -- ARRAY[16]   -> struct gpu_device_metrics
 *   gpu_per_pid                -- LRU_HASH    -> struct gpu_pid_metrics_aggregated
 *   gpu_per_pid_per_device     -- LRU_HASH    -> struct gpu_pid_metrics
 *
 * Consumer BPF programs may include this header (or copy the structs
 * verbatim) and reference the maps with __uint(pinning, LIBBPF_PIN_BY_NAME).
 * Consumers should always use BPF CO-RE relocations
 * (bpf_core_field_exists, BPF_CORE_READ) so the same gadget binary keeps
 * working against newer or older bridge versions.
 *
 * Naming is deliberately vendor-neutral (gpu_*, not nvml_*) so a future
 * AMD ROCm or Intel oneAPI bridge can publish the same map names and
 * struct layouts and let consumers work unchanged across vendors.
 */

#ifndef __GPU_TYPES_H
#define __GPU_TYPES_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

/* Bumped on incompatible struct layout changes. v1 = initial release.
 * Consumers are encouraged to rely on bpf_core_field_exists() rather than
 * version comparisons; the version field is mostly useful for non-BPF
 * userspace consumers (bpftool, custom Go tools) that don't have CO-RE.
 */
#define GPU_SCHEMA_VERSION 1

/* Max number of GPU devices the bridge will index. Sized for the largest
 * HGX system plus a small headroom.
 */
#define GPU_MAX_DEVICES 16

/* gpu_meta -- bridge state and freshness signal.
 *
 * One entry at key 0. Updated every poll tick. Consumers should compare
 * last_update_boottime_ns against bpf_ktime_get_boot_ns() and treat data
 * older than ~2x the bridge's poll interval as stale.
 */
struct gpu_meta {
	__u32 schema_version;
	__u32 n_devices;
	__u64 last_update_boottime_ns; /* CLOCK_BOOTTIME ns of last bridge tick */
	__u32 helper_pid;
	__u32 _reserved;
	__s64 clock_offset_ns; /* signed: (CLOCK_REALTIME - CLOCK_BOOTTIME) ns,
	                        * refreshed every poll tick. Consumers convert an
	                        * NVML wall-clock (CLOCK_REALTIME) timestamp to
	                        * CLOCK_BOOTTIME via: boottime = realtime - offset.
	                        */
};

/* gpu_device_metrics -- per-device metrics.
 *
 * Indexed by GPU device index (0 .. n_devices-1). Fields populated by the
 * bridge from NVML in v1; a field the underlying telemetry source cannot
 * provide is reported as zero.
 */
struct gpu_device_metrics {
	__u64 timestamp_ns;

	__u32 sm_util_pct; /* 0-100 */
	__u32 mem_util_pct; /* 0-100 */

	__u64 mem_total; /* total physical VRAM, bytes */
	__u64 mem_used; /* user-allocated VRAM (excludes mem_reserved); bytes.
	                 * mem_free = mem_total - mem_used - mem_reserved.
	                 * Note: nvidia-smi's "memory.used" matches this field
	                 * (NOT NVML v2 docs which claim used includes reserved).
	                 */
	__u64 mem_reserved; /* driver/firmware overhead, bytes */

	__u32 temp_c;
	__u32 power_mw; /* milliwatts */

	__u32 sm_clock_mhz;
	__u32 mem_clock_mhz;

	__u64 throttle_reasons; /* NVML clocksEventReasons bitmask */

	__u64 pcie_tx_kbps;
	__u64 pcie_rx_kbps;

	__u32 enc_util_pct; /* video encoder */
	__u32 dec_util_pct; /* video decoder */

	__u64 nvlink_tx_kbps; /* 0 on non-NVLink GPUs */
	__u64 nvlink_rx_kbps;

	__u64 ecc_corrected_total;
	__u64 ecc_uncorrected_total;

	__u32 fan_speed_pct; /* 0 if no controllable fan */
	__u32 compute_mode; /* NVML_COMPUTEMODE_* enum value */
};

/* gpu_pid_metrics -- detailed per-(PID, device) metrics.
 *
 * Key encoding: u64 = ((pid << 32) | device_idx). A single host PID can
 * hold contexts on multiple GPUs (common on multi-GPU training); each is
 * a separate entry.
 */
struct gpu_pid_metrics {
	__u64 timestamp_ns;
	__u64 used_gpu_memory;

	__u32 sm_util_pct;
	__u32 mem_util_pct;
	__u32 enc_util_pct;
	__u32 dec_util_pct;

	__u8 gpu_device;
	__u8 mig_instance; /* 0 in v1; MIG support deferred */
	__u16 _pad;
};

/* gpu_pid_metrics_aggregated -- convenience per-PID view.
 *
 * Key is the host PID (u32). The bridge maintains this map alongside
 * gpu_per_pid_per_device for consumers that don't care which GPU a
 * process is running on. Values are aggregated across devices:
 *
 *   used_gpu_memory_total = sum across devices
 *   sm_util_pct_max       = max across devices
 *   mem_util_pct_max      = max across devices
 *   gpu_device_primary    = first-seen device, or 0xFF for multi-device
 *   device_count          = number of devices this PID is on
 */
struct gpu_pid_metrics_aggregated {
	__u64 timestamp_ns;
	__u64 used_gpu_memory_total;

	__u32 sm_util_pct_max;
	__u32 mem_util_pct_max;

	__u8 gpu_device_primary;
	__u8 device_count;
	__u16 _pad;
};

#define GPU_DEVICE_PRIMARY_MULTI 0xFF

#endif /* __GPU_TYPES_H */
