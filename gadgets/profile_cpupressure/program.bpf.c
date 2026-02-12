// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 The Inspektor Gadget authors

// CPU Pressure Gadget
// Tracks:
// 1. Runqueue latency (time processes wait in the run queue before being scheduled)
// 2. CFS throttling events (when bandwidth limiting throttles/unthrottles processes)

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include <gadget/bits.bpf.h>
#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/kernel_stack_map.h>
#include <gadget/macros.h>
#include <gadget/maps.bpf.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>
#include <gadget/user_stack_map.h>

#define MAX_ENTRIES 10240
#define PROFILER_MAX_SLOTS 27

// ============================================================
// PARAMETERS
// ============================================================

const volatile bool collect_kernel_stacks = false;
GADGET_PARAM(collect_kernel_stacks);

// collect_ustack is defined in user_stack_map.h

const volatile bool per_process = true;
GADGET_PARAM(per_process);

const volatile bool targ_ms = false;
GADGET_PARAM(targ_ms);

// ============================================================
// RUNQUEUE LATENCY HISTOGRAM DATA STRUCTURES
// ============================================================

// Key for runqueue latency histogram
// When per_process=true: aggregate by (pid, comm, mntns_id)
// When per_process=false: aggregate by (mntns_id) only
struct runqlat_key {
	gadget_pid pid;
	gadget_comm comm[TASK_COMM_LEN];
	gadget_mntns_id mntns_id;
};

// Value containing histogram slots and metrics
struct runqlat_value {
	gadget_histogram_slot__u64 latency[PROFILER_MAX_SLOTS];
	__u64 total_ns;
	__u64 count;
};

// ============================================================
// CFS THROTTLE EVENT STRUCTURE
// ============================================================

struct cfs_throttle_event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;
	__u64 throttle_duration_ns;
	__u8 is_throttle; // 1 = throttle start, 0 = unthrottle
	gadget_kernel_stack kern_stack_raw;
	struct gadget_user_stack user_stack_raw;
};

// ============================================================
// MAPS
// ============================================================

// Runqueue latency histogram map
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct runqlat_key);
	__type(value, struct runqlat_value);
} runqlat_hists SEC(".maps");

GADGET_MAPITER(runqlat, runqlat_hists);

// Map to track throttle start times per cfs_rq
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u64);
} throttle_start SEC(".maps");

// Ring buffer for CFS throttle events
GADGET_TRACER_MAP(cfs_events, 1024 * 256);
GADGET_TRACER(cfs_throttle, cfs_events, cfs_throttle_event);

// ============================================================
// RUNQUEUE LATENCY TRACKING (wakeup + switch method)
// ============================================================

// This approach works without CONFIG_SCHEDSTATS by tracking:
// 1. When a task is woken up (becomes runnable)
// 2. When it actually gets scheduled to run
// The difference is the runqueue latency.

// Map to track wakeup timestamps per task
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, __u64);
} wakeup_start SEC(".maps");

// Helper to record wakeup time
static __always_inline int trace_enqueue(struct task_struct *p)
{
	__u32 pid = BPF_CORE_READ(p, pid);
	__u64 ts;

	// Skip kernel threads (pid 0)
	if (pid == 0)
		return 0;

	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&wakeup_start, &pid, &ts, BPF_ANY);
	return 0;
}

// Track when a task is woken up (becomes runnable)
SEC("tp_btf/sched_wakeup")
int BPF_PROG(ig_runqlat_wakeup, struct task_struct *p)
{
	return trace_enqueue(p);
}

// Also track newly created tasks
SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(ig_runqlat_wakeup_new, struct task_struct *p)
{
	return trace_enqueue(p);
}

// Calculate runqueue latency when task starts running
SEC("tp_btf/sched_switch")
int BPF_PROG(ig_runqlat_switch, bool preempt, struct task_struct *prev,
	     struct task_struct *next, unsigned int prev_state)
{
	struct runqlat_key key = {};
	struct runqlat_value *valp;
	static const struct runqlat_value zero = {};
	__u32 pid;
	__u64 *tsp, delta, ts;
	u64 slot;

	// Get the PID of the task that is about to run
	pid = BPF_CORE_READ(next, pid);
	if (pid == 0)
		return 0;

	// Lookup wakeup timestamp
	tsp = bpf_map_lookup_elem(&wakeup_start, &pid);
	if (!tsp)
		return 0;

	// Calculate runqueue latency
	ts = bpf_ktime_get_ns();
	delta = ts - *tsp;

	// Clean up the entry
	bpf_map_delete_elem(&wakeup_start, &pid);

	// Get mount namespace ID for filtering
	gadget_mntns_id mntns_id = BPF_CORE_READ(next, nsproxy, mnt_ns, ns.inum);

	// Filter by mount namespace (container filter)
	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	key.mntns_id = mntns_id;

	// If per_process mode, include process details in key
	if (per_process) {
		key.pid = BPF_CORE_READ(next, tgid);
		bpf_probe_read_kernel_str(&key.comm, sizeof(key.comm), next->comm);
	}

	// Lookup or initialize histogram entry
	valp = bpf_map_lookup_or_try_init(&runqlat_hists, &key, &zero);
	if (!valp)
		return 0;

	// Convert delay to desired unit (microseconds by default, milliseconds if targ_ms)
	u64 latency;
	if (targ_ms)
		latency = delta / 1000000U;
	else
		latency = delta / 1000U; // Convert ns to us

	// Get histogram slot using log2-based bucketing
	slot = get_slot_idx(latency);
	if (slot >= PROFILER_MAX_SLOTS)
		slot = PROFILER_MAX_SLOTS - 1;

	// Update histogram and counters atomically
	__sync_fetch_and_add(&valp->latency[slot], 1);
	__sync_fetch_and_add(&valp->total_ns, delta);
	__sync_fetch_and_add(&valp->count, 1);

	return 0;
}

// ============================================================
// CFS THROTTLING KPROBES
// ============================================================

// throttle_cfs_rq is called when CFS bandwidth control throttles a runqueue
// This happens when a cgroup has exhausted its CPU quota
SEC("kprobe/throttle_cfs_rq")
int BPF_KPROBE(ig_cfs_throttle, struct cfs_rq *cfs_rq)
{
	struct cfs_throttle_event *event;
	u64 key = (u64)cfs_rq;
	u64 ts = bpf_ktime_get_ns();

	// Check if we should discard based on current task
	if (gadget_should_discard_data_current())
		return 0;

	// Record throttle start time for duration calculation
	bpf_map_update_elem(&throttle_start, &key, &ts, BPF_ANY);

	// Emit throttle start event
	event = gadget_reserve_buf(&cfs_events, sizeof(*event));
	if (!event)
		return 0;

	event->timestamp_raw = bpf_ktime_get_boot_ns();
	event->is_throttle = 1;
	event->throttle_duration_ns = 0;

	// Populate process info from current context
	// Note: This may not be the throttled process itself, but gives useful correlation
	gadget_process_populate(&event->proc);

	// Collect kernel stack if enabled
	if (collect_kernel_stacks)
		event->kern_stack_raw = gadget_get_kernel_stack(ctx);
	else
		event->kern_stack_raw = -1;

	// Collect user stack if enabled (controlled by collect_ustack param)
	gadget_get_user_stack(ctx, &event->user_stack_raw);

	gadget_submit_buf(ctx, &cfs_events, event, sizeof(*event));
	return 0;
}

// unthrottle_cfs_rq is called when CFS unthrottles a runqueue
// This happens when a new period begins and quota is replenished
SEC("kprobe/unthrottle_cfs_rq")
int BPF_KPROBE(ig_cfs_unthrottle, struct cfs_rq *cfs_rq)
{
	struct cfs_throttle_event *event;
	u64 key = (u64)cfs_rq;
	u64 *start_ts;
	u64 duration = 0;

	// Check if we should discard based on current task
	if (gadget_should_discard_data_current())
		return 0;

	// Calculate throttle duration
	start_ts = bpf_map_lookup_elem(&throttle_start, &key);
	if (start_ts) {
		duration = bpf_ktime_get_ns() - *start_ts;
		bpf_map_delete_elem(&throttle_start, &key);
	}

	// Emit unthrottle event with duration
	event = gadget_reserve_buf(&cfs_events, sizeof(*event));
	if (!event)
		return 0;

	event->timestamp_raw = bpf_ktime_get_boot_ns();
	event->is_throttle = 0;
	event->throttle_duration_ns = duration;

	// Populate process info from current context
	gadget_process_populate(&event->proc);

	// Collect kernel stack if enabled
	if (collect_kernel_stacks)
		event->kern_stack_raw = gadget_get_kernel_stack(ctx);
	else
		event->kern_stack_raw = -1;

	// Collect user stack if enabled
	gadget_get_user_stack(ctx, &event->user_stack_raw);

	gadget_submit_buf(ctx, &cfs_events, event, sizeof(*event));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
