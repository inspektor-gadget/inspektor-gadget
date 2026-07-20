// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 The Inspektor Gadget authors */

/*
 * Minimal CI gadget exercising SEC("iter/bpf_map_elem") together with
 * GADGET_ITER_TARGET_MAP. The gadget declares one map with
 * LIBBPF_PIN_BY_NAME, attaches an iter program to it, and emits one event
 * per (key, value) pair via seq_file. Iteration is non-destructive: entries
 * remain in the map after each ig run.
 *
 * The map is intentionally pinned by name and uses LRU_HASH (rejected by
 * GADGET_MAPITER) so this also covers the case where another process pins
 * the map externally and the gadget reuses it through bpffs.
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include <gadget/macros.h>
#include <gadget/types.h>

struct test_key {
	__u32 pid;
};

struct test_value {
	__u64 timestamp_ns;
	__u32 sm_util_pct;
	__u32 mem_util_pct;
	__u64 used_gpu_memory;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct test_key);
	__type(value, struct test_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} test_iter_map SEC(".maps");

struct test_event {
	__u32 pid;
	__u32 sm_util_pct;
	__u32 mem_util_pct;
	__u32 _pad;
	__u64 used_gpu_memory;
	__u64 timestamp_ns;
};

GADGET_ITER(map_entries, test_event, dump_test_iter_map);
GADGET_ITER_TARGET_MAP(dump_test_iter_map, test_iter_map);

SEC("iter/bpf_map_elem")
int dump_test_iter_map(struct bpf_iter__bpf_map_elem *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct test_key *key = ctx->key;
	struct test_value *val = ctx->value;

	if (!key || !val)
		return 0;

	struct test_event ev = {
		.pid = key->pid,
		.sm_util_pct = val->sm_util_pct,
		.mem_util_pct = val->mem_util_pct,
		.used_gpu_memory = val->used_gpu_memory,
		.timestamp_ns = val->timestamp_ns,
	};

	bpf_seq_write(seq, &ev, sizeof(ev));
	return 0;
}

char __license[] SEC("license") = "GPL";
