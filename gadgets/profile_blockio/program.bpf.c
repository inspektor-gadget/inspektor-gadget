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
#define DISK_NAME_LEN 32

#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)

#define MKDEV(ma, mi) (((ma) << MINORBITS) | (mi))

const volatile bool filter_cg = false;
const volatile bool targ_per_disk = false;
const volatile bool targ_per_flag = false;
const volatile bool targ_queued = false;
const volatile bool targ_ms = false;
const volatile bool filter_dev = false;
const volatile __u32 targ_dev = 0;

extern int LINUX_KERNEL_VERSION __kconfig;

struct hist_key {
	__u32 cmd_flags;
	__u32 dev;
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

GADGET_MAPITER(blockio, hists);

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct request *);
	__type(value, u64);
} start SEC(".maps");

static struct hist_value initial_hist;

static __always_inline int trace_rq_start(struct request *rq, int issue)
{
	if (issue && targ_queued && BPF_CORE_READ(rq, q, elevator))
		return 0;

	u64 ts = bpf_ktime_get_ns();

	if (filter_dev) {
		struct gendisk *disk = get_disk(rq);
		u32 dev;

		dev = disk ? MKDEV(BPF_CORE_READ(disk, major),
				   BPF_CORE_READ(disk, first_minor)) :
			     0;
		if (targ_dev != dev)
			return 0;
	}
	bpf_map_update_elem(&start, &rq, &ts, 0);
	return 0;
}

// https://github.com/torvalds/linux/commit/a54895fa057c67700270777f7661d8d3c7fda88a
// -       TP_PROTO(struct request_queue *q, struct request *rq),
// +       TP_PROTO(struct request *rq),

// struct request and struct request_queue are likely different in the current
// kernel and in vmlinux.h. We don't need recursive compatibility checks on
// each field of the struct because we only use this to check the prototype of
// the tracepoints. We use empty structs so none of the fields are checked by
// bpf_core_type_matches().
struct request___empty {};
struct request_queue___empty {};

typedef void (*btf_trace_block_rq_insert___new)(void *,
						struct request___empty *);
typedef void (*btf_trace_block_rq_insert___old)(void *,
						struct request_queue___empty *q,
						struct request___empty *);
typedef void (*btf_trace_block_rq_issue___new)(void *,
					       struct request___empty *);
typedef void (*btf_trace_block_rq_issue___old)(void *,
					       struct request_queue___empty *q,
					       struct request___empty *);

SEC("raw_tp/block_rq_insert")
int ig_profio_ins(u64 *ctx)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	if (bpf_core_type_matches(btf_trace_block_rq_insert___new)) {
		// After commit a54895fa (v5.11-rc1)
		return trace_rq_start((void *)ctx[0], false);
	} else if (bpf_core_type_matches(btf_trace_block_rq_insert___old)) {
		// Before commit a54895fa (v5.11-rc1)
		return trace_rq_start((void *)ctx[1], false);
	} else {
		// Couldn't detect block/block_rq_insert tracepoint
		bpf_core_unreachable();
		return 0;
	}
}

SEC("raw_tp/block_rq_issue")
int ig_profio_iss(u64 *ctx)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	if (bpf_core_type_matches(btf_trace_block_rq_issue___new)) {
		// After commit a54895fa (v5.11-rc1)
		return trace_rq_start((void *)ctx[0], true);
	} else if (bpf_core_type_matches(btf_trace_block_rq_issue___old)) {
		// Before commit a54895fa (v5.11-rc1)
		return trace_rq_start((void *)ctx[1], true);
	} else {
		// Couldn't detect block/block_rq_issue tracepoint
		bpf_core_unreachable();
		return 0;
	}
}

SEC("raw_tp/block_rq_complete")
int BPF_PROG(ig_profio_done, struct request *rq, int error,
	     unsigned int nr_bytes)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	u64 slot, *tsp, ts = bpf_ktime_get_ns();
	struct hist_key hkey = {};
	struct hist_value *histp;
	s64 delta;

	tsp = bpf_map_lookup_elem(&start, &rq);
	if (!tsp)
		return 0;
	delta = (s64)(ts - *tsp);
	if (delta < 0)
		goto cleanup;

	if (targ_per_disk) {
		struct gendisk *disk = get_disk(rq);

		hkey.dev = disk ? MKDEV(BPF_CORE_READ(disk, major),
					BPF_CORE_READ(disk, first_minor)) :
				  0;
	}
	if (targ_per_flag)
		hkey.cmd_flags = BPF_CORE_READ(rq, cmd_flags);

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
	bpf_map_delete_elem(&start, &rq);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
