// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 The Inspektor Gadget authors */

/*
 * CI gadget exercising the gpu-ebpf-bridge four-map contract
 * end-to-end. Declares the bridge's gpu_device map with
 * LIBBPF_PIN_BY_NAME, iterates it non-destructively via
 * SEC("iter/bpf_map_elem") + GADGET_ITER_TARGET_MAP, and emits
 * one event per populated device slot.
 *
 * The integration test starts an out-of-tree gpu-ebpf-bridge
 * subprocess in --mode=mock, waits for the pinned maps to exist,
 * runs this gadget, and asserts the emitted events match the mock
 * backend's deterministic output. That flow validates:
 *
 *   1. The bridge creates the four maps and pins them at
 *      /sys/fs/bpf/gpu_* with correct BTF-typed values.
 *   2. LIBBPF_PIN_BY_NAME on the consumer side reuses the
 *      externally-pinned map instead of creating a fresh one.
 *   3. SEC("iter/bpf_map_elem") + GADGET_ITER_TARGET_MAP wires
 *      the iter program to the external map correctly and reads
 *      it non-destructively.
 *
 * Struct gpu_device_metrics is copied verbatim from
 * include/gadget/gpu_types.h (GPU_SCHEMA_VERSION 1).
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include <gadget/macros.h>
#include <gadget/types.h>

#define GPU_MAX_DEVICES 16

/* Layout must match struct gpu_device_metrics in
 * include/gadget/gpu_types.h. */
struct gpu_device_metrics {
	__u64 timestamp_ns;

	__u32 sm_util_pct;
	__u32 mem_util_pct;

	__u64 mem_total;
	__u64 mem_used;
	__u64 mem_reserved;

	__u32 temp_c;
	__u32 power_mw;

	__u32 sm_clock_mhz;
	__u32 mem_clock_mhz;

	__u64 throttle_reasons;

	__u64 pcie_tx_kbps;
	__u64 pcie_rx_kbps;

	__u32 enc_util_pct;
	__u32 dec_util_pct;

	__u64 nvlink_tx_kbps;
	__u64 nvlink_rx_kbps;

	__u64 ecc_corrected_total;
	__u64 ecc_uncorrected_total;

	__u32 fan_speed_pct;
	__u32 compute_mode;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, GPU_MAX_DEVICES);
	__type(key, __u32);
	__type(value, struct gpu_device_metrics);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} gpu_device SEC(".maps");

struct gpu_event {
	__u32 device;
	__u32 sm_util_pct;
	__u32 mem_util_pct;
	__u32 temp_c;
	__u32 power_mw;
	__u32 _pad;
	__u64 mem_used;
	__u64 mem_total;
	__u64 timestamp_ns;
};

GADGET_ITER(gpu_devices, gpu_event, dump_gpu_devices);
GADGET_ITER_TARGET_MAP(dump_gpu_devices, gpu_device);

SEC("iter/bpf_map_elem")
int dump_gpu_devices(struct bpf_iter__bpf_map_elem *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	__u32 *key = ctx->key;
	struct gpu_device_metrics *val = ctx->value;

	if (!key || !val)
		return 0;

	/* Skip unpopulated ARRAY slots (the bridge writes timestamp_ns
	 * on every update; a zero value means the slot was never
	 * touched). */
	if (val->timestamp_ns == 0)
		return 0;

	struct gpu_event ev = {
		.device = *key,
		.sm_util_pct = val->sm_util_pct,
		.mem_util_pct = val->mem_util_pct,
		.temp_c = val->temp_c,
		.power_mw = val->power_mw,
		.mem_used = val->mem_used,
		.mem_total = val->mem_total,
		.timestamp_ns = val->timestamp_ns,
	};

	bpf_seq_write(seq, &ev, sizeof(ev));
	return 0;
}

char __license[] SEC("license") = "GPL";
