// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 The Inspektor Gadget authors */

/*
 * This program is adapted from the 'profile_qdisc_latency' gadget.
 * It serves as a test gadget to ensure consistent behavior for the
 * 'inspect' command across environments and updates.
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <gadget/bits.bpf.h>
#include <gadget/core_fixes.bpf.h>
#include <gadget/types.h>
#include <gadget/macros.h>

#ifndef PROFILER_MAX_SLOTS
#define PROFILER_MAX_SLOTS 27
#endif /* !PROFILER_MAX_SLOTS */

#define MAX_ENTRIES 10240

const volatile int ifindex = -1;
const volatile bool targ_ms = false;

GADGET_PARAM(ifindex);
GADGET_PARAM(targ_ms);

struct hist_key {
	u8 unused;
};

// hist_value is used as value for profiler hash map.
struct hist_value {
	gadget_histogram_slot__u32 latency[PROFILER_MAX_SLOTS];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct hist_key);
	__type(value, struct hist_value);
} map1 SEC(".maps");

GADGET_MAPITER(qdisc, map1);

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct sk_buff *);
	__type(value, u64);
} map2 SEC(".maps");

SEC("program1")
int BPF_PROG(qdisc_enqueue, struct sk_buff *skb)
{
	u64 ts = bpf_ktime_get_ns();

	bpf_map_update_elem(&map2, &skb, &ts, 0);
	return 0;
}

SEC("program2")
int BPF_PROG(qdisc_dequeue, struct sk_buff *skb)
{
	static struct hist_value initial_hist;
	struct hist_value *histp;
	struct hist_key hkey = { 0 };

	histp = bpf_map_lookup_elem(&map1, &hkey);
	if (!histp) {
		bpf_map_update_elem(&map1, &hkey, &initial_hist, 0);
		histp = bpf_map_lookup_elem(&map1, &hkey);
	}
	return 0;
}

SEC("program3")
int BPF_PROG(consume_skb, struct sk_buff *skb)
{
	u64 *tsp, ts = bpf_ktime_get_ns();
	s64 delta;

	tsp = bpf_map_lookup_elem(&map2, &skb);
	if (!tsp)
		return 0;
	delta = (s64)(ts - *tsp);
	if (delta < 0)
		goto cleanup;
cleanup:
	bpf_map_delete_elem(&map2, &skb);

	return 0;
}

SEC("program4")
int BPF_PROG(kfree_skb, struct sk_buff *skb)
{
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
