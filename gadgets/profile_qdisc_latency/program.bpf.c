// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
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

const volatile bool targ_ms = false;

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
} hists SEC(".maps");

GADGET_MAPITER(qdisc, hists);

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct request *);
	__type(value, u64);
} start SEC(".maps");

static struct hist_value initial_hist;

static __always_inline int trace_start(struct sk_buff *skb, int issue)
{
	u64 ts = bpf_ktime_get_ns();

	bpf_map_update_elem(&start, &skb, &ts, 0);
	return 0;
}

static __always_inline void trace_stop(struct sk_buff *skb)
{
	u64 slot, *tsp, ts = bpf_ktime_get_ns();
	struct hist_key hkey = { 0 };
	struct hist_value *histp;
	s64 delta;

	tsp = bpf_map_lookup_elem(&start, &skb);
	if (!tsp)
		return;
	delta = (s64)(ts - *tsp);
	if (delta < 0)
		goto cleanup;

	histp = bpf_map_lookup_elem(&hists, &hkey);
	if (!histp) {
		bpf_map_update_elem(&hists, &hkey, &initial_hist, 0);
		histp = bpf_map_lookup_elem(&hists, &hkey);
		if (!histp)
			goto cleanup;
	}

	if (targ_ms)
		delta /= 1000000U;
	else
		delta /= 1000U;
	slot = log2l(delta);
	if (slot >= PROFILER_MAX_SLOTS)
		slot = PROFILER_MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->latency[slot], 1);

cleanup:
	bpf_map_delete_elem(&start, &skb);
}

SEC("raw_tp/qdisc_enqueue")
int BPF_PROG(qdisc_enqueue, struct Qdisc *qdisc, const struct netdev_queue *txq,
	     struct sk_buff *skb)
{
	u64 ts = bpf_ktime_get_ns();

	bpf_map_update_elem(&start, &skb, &ts, 0);
	return 0;
}

SEC("raw_tp/qdisc_dequeue")
int BPF_PROG(qdisc_dequeue, struct Qdisc *qdisc, const struct netdev_queue *txq,
	     int packets, struct sk_buff *skb)
{
	trace_stop(skb);
	return 0;
}

SEC("raw_tp/consume_skb")
int BPF_PROG(consume_skb, struct sk_buff *skb, void *location)
{
	trace_stop(skb);
	return 0;
}

SEC("raw_tp/kfree_skb")
int BPF_PROG(kfree_skb, struct sk_buff *skb, void *location,
	     enum skb_drop_reason reason)
{
	trace_stop(skb);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
