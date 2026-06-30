// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 The Inspektor Gadget authors */

/*
 * gpu_top: report current GPU device telemetry from the gpu-ebpf-bridge.
 *
 * This gadget is a consumer of the bpffs-pinned maps published by the
 * gpu-ebpf-bridge daemon (see docs/reference/gpu-ebpf-bridge.md).
 *
 * The bridge publishes four maps under /sys/fs/bpf/:
 *
 *   gpu_meta                ARRAY[1]   -> struct gpu_meta
 *   gpu_device              ARRAY[16]  -> struct gpu_device_metrics
 *   gpu_per_pid             LRU_HASH   -> struct gpu_pid_metrics_aggregated
 *   gpu_per_pid_per_device  LRU_HASH   -> struct gpu_pid_metrics
 *
 * gpu_top iterates gpu_device via SEC("iter/bpf_map_elem") and emits one
 * event per active GPU. Iteration is non-destructive: ig run can be
 * repeated to refresh.
 *
 * The map is reused from bpffs by virtue of __uint(pinning,
 * LIBBPF_PIN_BY_NAME): the gadget will fail to load if the bridge daemon
 * is not running (i.e. the pinned map does not exist), which is the
 * intended behaviour.
 *
 * Struct gpu_device_metrics is copied verbatim from
 * include/gpu_types.h (GPU_SCHEMA_VERSION 1). Keep this declaration in
 * sync with the bridge's contract; consumers are encouraged to use
 * bpf_core_field_exists() for fields added in newer schema versions.
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include <gadget/macros.h>
#include <gadget/types.h>

#define GPU_BRIDGE_WANT_DEVICE
#include <gadget/gpu_bridge_maps.h>

/* Event layout exposed to userspace. Order is kept close to the most
 * useful columns for an at-a-glance "GPU top": device id, utilization,
 * memory, thermal/power. Less-used telemetry (clocks, throttle reasons,
 * PCIe/NVLink, ECC) is included for completeness and hidden by default
 * in gadget.yaml.
 *
 * mem_*_raw fields are typed as gadget_bytes (a __u64 typedef); the
 * formatters operator picks them up by the `_raw` suffix and adds
 * corresponding string fields (`mem_used`, `mem_total`, `mem_reserved`)
 * containing the human-readable forms ("15 GB" instead of
 * "16106127360"). Those string fields are what appears in the default
 * column output. The numeric `_raw` fields stay available for JSON
 * consumers and for further math. */
struct gpu_top_event {
	__u32 device;

	__u32 sm_util_pct;
	__u32 mem_util_pct;

	gadget_bytes mem_used_raw;
	gadget_bytes mem_total_raw;
	gadget_bytes mem_reserved_raw;

	__u32 temp_c;
	__u32 power_mw;

	__u32 sm_clock_mhz;
	__u32 mem_clock_mhz;

	__u32 enc_util_pct;
	__u32 dec_util_pct;

	__u64 throttle_reasons;

	__u64 pcie_tx_kbps;
	__u64 pcie_rx_kbps;

	__u64 nvlink_tx_kbps;
	__u64 nvlink_rx_kbps;

	__u64 ecc_corrected_total;
	__u64 ecc_uncorrected_total;

	__u32 fan_speed_pct;
	__u32 compute_mode;

	__u64 timestamp_ns;
};

GADGET_ITER(gpu_top, gpu_top_event, dump_gpu_devices);
GADGET_ITER_TARGET_MAP(dump_gpu_devices, gpu_device);

SEC("iter/bpf_map_elem")
int dump_gpu_devices(struct bpf_iter__bpf_map_elem *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	__u32 *key = ctx->key;
	struct gpu_device_metrics *val = ctx->value;

	if (!key || !val)
		return 0;

	/* The bridge publishes the map as ARRAY[16]; slots for devices
	 * the bridge did not write are zero-initialised. timestamp_ns is
	 * the freshness signal: skip slots the bridge has never touched. */
	if (val->timestamp_ns == 0)
		return 0;

	/* Aggregate initializers in C do not touch padding bytes between
	 * fields (e.g. the 4 bytes between the u32 mem_util_pct and the
	 * u64 mem_used_raw). Leaving them uninitialised trips the BPF
	 * verifier: "invalid indirect read from stack ... size 136".
	 * Zero the whole struct first, then fill in fields. */
	struct gpu_top_event ev;
	__builtin_memset(&ev, 0, sizeof(ev));
	ev.device = *key;
	ev.sm_util_pct = val->sm_util_pct;
	ev.mem_util_pct = val->mem_util_pct;
	ev.mem_used_raw = val->mem_used;
	ev.mem_total_raw = val->mem_total;
	ev.mem_reserved_raw = val->mem_reserved;
	ev.temp_c = val->temp_c;
	ev.power_mw = val->power_mw;
	ev.sm_clock_mhz = val->sm_clock_mhz;
	ev.mem_clock_mhz = val->mem_clock_mhz;
	ev.enc_util_pct = val->enc_util_pct;
	ev.dec_util_pct = val->dec_util_pct;
	ev.throttle_reasons = val->throttle_reasons;
	ev.pcie_tx_kbps = val->pcie_tx_kbps;
	ev.pcie_rx_kbps = val->pcie_rx_kbps;
	ev.nvlink_tx_kbps = val->nvlink_tx_kbps;
	ev.nvlink_rx_kbps = val->nvlink_rx_kbps;
	ev.ecc_corrected_total = val->ecc_corrected_total;
	ev.ecc_uncorrected_total = val->ecc_uncorrected_total;
	ev.fan_speed_pct = val->fan_speed_pct;
	ev.compute_mode = val->compute_mode;
	ev.timestamp_ns = val->timestamp_ns;

	bpf_seq_write(seq, &ev, sizeof(ev));
	return 0;
}

char __license[] SEC("license") = "GPL";
