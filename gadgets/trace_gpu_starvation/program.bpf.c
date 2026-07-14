// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 The Inspektor Gadget authors */

/*
 * trace_gpu_starvation: detect threads that burn CPU while the GPU their
 * process owns sits idle.
 *
 * Hook: kprobe/finish_task_switch. This scheduler function runs just after
 * a context switch, in the context of the INCOMING task (current == next),
 * and receives the outgoing task (prev) as its first argument.
 *
 * Why a kprobe and not the sched_switch tracepoint: the whole point of this
 * gadget is to symbolize Python (and other high-level) user stacks via IG's
 * OTel eBPF-profiler integration. That integration reaches the OTel unwinder
 * through a bpf_tail_call into a BPF_PROG_TYPE_KPROBE program, and
 * bpf_tail_call requires the caller and callee to share the same program
 * type. Only kprobe-family programs (kprobe/kretprobe/uprobe/uretprobe) can
 * therefore obtain OTel stacks; perf_event and tracepoint/tp_btf programs
 * cannot. finish_task_switch is a plain (non-NOKPROBE) kernel function, so a
 * kprobe on it gives us both scheduler visibility and OTel-capable stacks.
 *
 * Because OTel always symbolizes `current`, and at finish_task_switch that is
 * the incoming task, we capture the user stack at schedule-IN (when the
 * thread is current, so the unwind is valid) and accumulate its on-CPU
 * duration at schedule-OUT (when the same thread later reappears as prev).
 * The stack captured at schedule-in is the resume PC of exactly the slice we
 * then measure -- for an involuntarily-preempted CPU-bound loop this is the
 * hot loop, which is what we want to attribute.
 *
 * struct gpu_pid_metrics_aggregated / struct gpu_meta are copied verbatim
 * from include/gadget/gpu_types.h (GPU_SCHEMA_VERSION 1). Consumers reference
 * the bridge's pinned maps with __uint(pinning, LIBBPF_PIN_BY_NAME).
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include <gadget/types.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/buffer.h>
#include <gadget/user_stack_map.h>
#include <gadget/kernel_stack_map.h>

/* ---- bridge schema + pinned maps (shared with the other GPU gadgets) ---- */

#define GPU_BRIDGE_WANT_PER_PID
#define GPU_BRIDGE_WANT_DEVICE
#define GPU_BRIDGE_WANT_META
#include <gadget/gpu_bridge_maps.h>

/* ---- params ---- */

const volatile __u64 min_idle_ms = 1000;
GADGET_PARAM(min_idle_ms);

const volatile __u64 min_gpu_mem_bytes = 1;
GADGET_PARAM(min_gpu_mem_bytes);

const volatile __u64 stale_threshold_ms = 300;
GADGET_PARAM(stale_threshold_ms);

const volatile bool collect_kstack = false;
GADGET_PARAM(collect_kstack);

/* collect_ustack is declared by <gadget/user_stack_map.h>. */

/* Emit at most one event per second per thread. */
#define EMIT_WINDOW_NS (1000ULL * 1000ULL * 1000ULL)

/* ---- gadget state ---- */

struct oncpu_info {
	__u64 start_ns; /* schedule-in timestamp (CLOCK_BOOTTIME) */
	__u8 gated; /* 1 if proc+ustack below were captured */
	__u8 _pad[7];
	struct gadget_process proc;
	struct gadget_user_stack ustack;
};

struct thread_accum {
	__u64 window_start_ns;
	__u64 cpu_time_ns;
	__u32 hit_count;
	__u32 _pad; /* explicit tail padding: keeps the whole 24-byte map value
		     * initialized so bpf_map_update_elem(&accum, &init) does not
		     * trip the verifier's "invalid indirect read from stack"
		     * (uninitialized struct padding) check. */
};

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;

	struct gadget_user_stack ustack;
	gadget_kernel_stack kstack_raw;

	__u64 cpu_time_ns; /* on-CPU time accumulated while GPU idle, this window */
	__u64 idle_ns; /* GPU idle duration for this PID at emit time */
	__u32 hit_count; /* context-switch hits in this window */
};

/* Per-CPU scratch for struct oncpu_info: it is far too large for the 512-byte
 * BPF stack, and gadget_get_user_stack() calls a noinline tail-call helper
 * that tightens the per-frame limit further. Build the value here, then copy
 * into the oncpu map. See profile_cuda/program.bpf.c for the same pattern.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct oncpu_info);
} tmp_oncpu SEC(".maps");

/* Per-thread on-CPU state, keyed by thread pid. LRU_HASH so leaked entries
 * (thread died mid-slice, before its schedule-out) are eventually evicted;
 * a sched_process_exit cleanup handles the common case promptly.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32); /* thread pid */
	__type(value, struct oncpu_info);
} oncpu SEC(".maps");

/* Per-thread emit gate, keyed by thread pid. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32); /* thread pid */
	__type(value, struct thread_accum);
} accum SEC(".maps");

/* Per-device latch: the newest CLOCK_BOOTTIME timestamp at which the bridge
 * observed the device with non-zero SM utilization. Refreshed on every context
 * switch (any CPU) from the bridge's gpu_device snapshot, so the "GPU is
 * active" signal stays fresh from system-wide scheduling even while a
 * GPU-holding thread runs a long CPU slice without being scheduled out.
 *
 * Device-level SM utilization (~167ms NVML sampling resolution) is used
 * deliberately in place of per-process utilization: the per-process NVML API
 * only samples at ~1s and intermittently drops a busy process entirely, so it
 * cannot resolve sub-second GPU-idle stalls. "Is the GPU idle" is a device
 * property; gpu_holder() attributes it to a PID via the device that PID's GPU
 * memory lives on (gpu_device_primary). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, GPU_MAX_DEVICES);
	__type(key, __u32); /* device index */
	__type(value,
	       __u64); /* CLOCK_BOOTTIME ns of last device-active sample */
} device_last_active SEC(".maps");

/* Aggregate latch: max over all devices of device_last_active, maintained
 * alongside the per-device latch by the same updater program. Lets gpu_holder()
 * resolve the multi-device (gpu_device_primary == 0xFF) case with a single
 * lookup instead of a device loop, keeping the (large) finish_task_switch
 * program free of loops. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64); /* CLOCK_BOOTTIME ns, newest across all devices */
} device_last_active_any SEC(".maps");

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(gpu_starvation, events, event);

/* Device-activity latch updater. Runs as its OWN program on every context
 * switch (any CPU) so the "GPU is active" signal stays fresh from system-wide
 * scheduling even while a GPU-holding thread runs a long CPU slice without being
 * scheduled out. It is deliberately a separate program (not folded into
 * finish_task_switch) so its per-device loop gets an independent 1M-instruction
 * verifier budget: finish_task_switch already does kernel+user stack walks and
 * cannot absorb a device loop without blowing the limit.
 *
 * Device-level SM utilization (~167ms NVML sampling resolution) is used
 * deliberately in place of per-process utilization: the per-process NVML API
 * only samples at ~1s and intermittently drops a busy process entirely, so it
 * cannot resolve sub-second GPU-idle stalls. */
SEC("tracepoint/sched/sched_switch")
int ig_sched_switch_devlatch(void *ctx)
{
	__u32 zero = 0;
	struct gpu_meta *meta = bpf_map_lookup_elem(&gpu_meta, &zero);
	if (!meta)
		return 0;

		/* Constant trip count (verifier knows d < GPU_MAX_DEVICES) with unroll
	 * disabled keeps this a real, convergent loop. gpu_device is a 16-entry
	 * ARRAY, so unused slots read sm_util_pct == 0 and are skipped; a runtime
	 * n_devices bound is avoided because the verifier treats it as a
	 * full-range u32 and fails to converge the loop. */
#pragma clang loop unroll(disable)
	for (__u32 d = 0; d < GPU_MAX_DEVICES; d++) {
		/* Use a separate key variable for the map lookups: taking the
		 * address of the loop counter itself would spill it to the
		 * stack, where the verifier loses its bounds and rejects the
		 * loop as "infinite" (cannot prove the counter progresses). */
		__u32 key = d;
		struct gpu_device_metrics *dm =
			bpf_map_lookup_elem(&gpu_device, &key);
		if (!dm || dm->sm_util_pct == 0)
			continue;
		/* Device timestamp is CLOCK_REALTIME (bridge time.Now); convert
		 * to CLOCK_BOOTTIME: boottime = realtime - offset. Latch
		 * monotonically so a stale/racing read never rewinds it. */
		__u64 active_boot =
			dm->timestamp_ns - (__u64)meta->clock_offset_ns;
		__u64 *la = bpf_map_lookup_elem(&device_last_active, &key);
		if (la && active_boot > *la)
			*la = active_boot;
		__u64 *any =
			bpf_map_lookup_elem(&device_last_active_any, &zero);
		if (any && active_boot > *any)
			*any = active_boot;
	}
	return 0;
}

/* Does tgid currently hold at least min_gpu_mem_bytes of GPU memory, with
 * fresh bridge data? Fills *gm_out and *idle_out when true.
 */
static __always_inline bool
gpu_holder(__u32 tgid, __u64 now, struct gpu_pid_metrics_aggregated **gm_out,
	   __u64 *idle_out)
{
	struct gpu_pid_metrics_aggregated *gm =
		gpu_pid_holder(tgid, min_gpu_mem_bytes);
	if (!gm)
		return false;

	if (!gpu_meta_fresh(now, stale_threshold_ms))
		return false;

	/* Per-PID GPU-idle is derived from the DEVICE this PID's memory lives
	 * on. device_last_active holds the newest CLOCK_BOOTTIME at which that
	 * device was observed active (maintained by ig_sched_switch_devlatch);
	 * idle is the time elapsed since. A device never seen active latches 0,
	 * so idle spans the whole uptime (matches "allocated but never ran a
	 * kernel"). No device loop here: the multi-device case reads the
	 * precomputed aggregate latch, so this (large) program stays loop-free. */
	__u64 last_active_boot = 0;
	__u8 dev = gm->gpu_device_primary;
	__u32 key = (dev == GPU_DEVICE_PRIMARY_MULTI) ? 0 : dev;
	__u64 *la = (dev == GPU_DEVICE_PRIMARY_MULTI) ?
			    bpf_map_lookup_elem(&device_last_active_any, &key) :
			    bpf_map_lookup_elem(&device_last_active, &key);
	if (la)
		last_active_boot = *la;

	*gm_out = gm;
	*idle_out = now - last_active_boot;
	return true;
}

SEC("kprobe/finish_task_switch")
int BPF_KPROBE(ig_finish_task_switch, struct task_struct *prev)
{
	__u64 now = bpf_ktime_get_boot_ns();
	__u32 zero = 0;

	/* ---- (A) schedule-OUT: account the slice prev just ran ---- */
	__u32 prev_pid = BPF_CORE_READ(prev, pid);
	struct oncpu_info *oi = bpf_map_lookup_elem(&oncpu, &prev_pid);
	if (oi) {
		__u64 duration = now - oi->start_ns;
		__u32 prev_tgid = BPF_CORE_READ(prev, tgid);

		struct gpu_pid_metrics_aggregated *gm;
		__u64 idle_ns;
		if (oi->gated && gpu_holder(prev_tgid, now, &gm, &idle_ns) &&
		    idle_ns >= min_idle_ms * 1000000ULL) {
			/* Starvation confirmed for this slice. Accumulate into
			 * the per-thread window and emit at most 1/s.
			 */
			struct thread_accum *ta =
				bpf_map_lookup_elem(&accum, &prev_pid);
			if (!ta) {
				struct thread_accum init = {
					.window_start_ns = now,
					.cpu_time_ns = duration,
					.hit_count = 1,
				};
				bpf_map_update_elem(&accum, &prev_pid, &init,
						    BPF_ANY);
			} else {
				ta->cpu_time_ns += duration;
				ta->hit_count += 1;

				if (now - ta->window_start_ns >=
				    EMIT_WINDOW_NS) {
					struct event *ev = gadget_reserve_buf(
						&events, sizeof(*ev));
					if (ev) {
						ev->timestamp_raw = now;
						ev->proc = oi->proc;
						ev->ustack = oi->ustack;
						ev->kstack_raw =
							collect_kstack ?
								gadget_get_kernel_stack(
									ctx) :
								-1;
						ev->cpu_time_ns =
							ta->cpu_time_ns;
						ev->idle_ns = idle_ns;
						ev->hit_count = ta->hit_count;
						gadget_submit_buf(ctx, &events,
								  ev,
								  sizeof(*ev));
					}
					/* Reset the window. */
					ta->window_start_ns = now;
					ta->cpu_time_ns = 0;
					ta->hit_count = 0;
				}
			}
		}
		bpf_map_delete_elem(&oncpu, &prev_pid);
	}

	/* ---- (B) schedule-IN: current == next ---- */
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 next_pid = (__u32)pid_tgid;
	__u32 next_tgid = pid_tgid >> 32;
	if (next_pid == 0) /* swapper/idle */
		return 0;

	struct oncpu_info *ni = bpf_map_lookup_elem(&tmp_oncpu, &zero);
	if (!ni)
		return 0;
	ni->start_ns = now;
	ni->gated = 0;

	/* Capture the stack for any GPU-holding thread with fresh data. The
	 * idle threshold is deliberately NOT required here: it is re-checked at
	 * schedule-out (idle only grows), so capturing unconditionally for GPU
	 * holders avoids missing a thread whose GPU went idle mid-slice. GPU
	 * holders are few, so this is cheap.
	 */
	struct gpu_pid_metrics_aggregated *gm;
	__u64 idle_ns;
	if (!gadget_should_discard_data_current() &&
	    gpu_holder(next_tgid, now, &gm, &idle_ns)) {
		ni->gated = 1;
		gadget_process_populate(&ni->proc);
		gadget_get_user_stack(ctx, &ni->ustack);
	}

	bpf_map_update_elem(&oncpu, &next_pid, ni, BPF_ANY);
	return 0;
}

/* Clean up per-thread state promptly on thread exit (LRU eviction is the
 * backstop for the rare case a thread dies between schedule-in and its next
 * schedule-out).
 */
SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(void *ctx)
{
	__u32 pid = (__u32)bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&oncpu, &pid);
	bpf_map_delete_elem(&accum, &pid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
