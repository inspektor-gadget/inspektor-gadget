// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 The Inspektor Gadget authors */

/*
 * gpu_top_per_pid: report current per-process GPU usage from the
 * gpu-ebpf-bridge daemon.
 *
 * Companion gadget to gpu_top. Where gpu_top iterates the bridge's
 * per-device map, this iterates the bridge's per-PID aggregated map
 * (gpu_per_pid) and emits one event per PID with its GPU memory and
 * peak utilization across all devices.
 *
 * Each event carries a struct gadget_process so IG's container, pod,
 * and K8s enrichers add the runtime context automatically from the
 * mntns_id field — no extra plumbing in this gadget.
 *
 * The bridge map type is LRU_HASH, so it is not safe to iterate with
 * GADGET_MAPITER (which uses BPF_MAP_LOOKUP_AND_DELETE_BATCH and
 * drains the map). We use SEC("iter/bpf_map_elem") via
 * GADGET_ITER_TARGET_MAP for non-destructive iteration.
 *
 * Struct gpu_pid_metrics_aggregated is copied verbatim from
 * include/gpu_types.h (GPU_SCHEMA_VERSION 1).
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include <gadget/macros.h>
#include <gadget/types.h>

/* gpu_per_pid value layout from the bridge's include/gpu_types.h. */
struct gpu_pid_metrics_aggregated {
	__u64 timestamp_ns;
	__u64 used_gpu_memory_total;

	__u32 sm_util_pct_max;
	__u32 mem_util_pct_max;

	__u8  gpu_device_primary;
	__u8  device_count;
	__u16 _pad;
};

#define GPU_DEVICE_PRIMARY_MULTI 0xFF

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct gpu_pid_metrics_aggregated);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} gpu_per_pid SEC(".maps");

/* Kfuncs for looking up the task_struct of a PID we read from the
 * bridge's map. iter/bpf_map_elem programs run in their own kernel
 * context (no current task), so this is how we get comm + mntns from
 * the entry's PID for the IG process / container enrichers. */
extern struct task_struct *bpf_task_from_pid(s32 pid) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

/* Event emitted to userspace. gadget_process triggers IG's automatic
 * enrichment (comm, container, pod, K8s) from the mntns_id we fill
 * below. mem_used_raw is gadget_bytes so the formatters operator adds
 * a human-readable string field "mem_used".
 */
struct gpu_top_per_pid_event {
	struct gadget_process proc;

	gadget_bytes mem_used_raw;

	__u32 sm_util_pct_max;
	__u32 mem_util_pct_max;

	__u8  gpu_device_primary;
	__u8  device_count;
	__u16 _pad;

	__u64 timestamp_ns;
};

GADGET_ITER(gpu_top_per_pid, gpu_top_per_pid_event, dump_gpu_per_pid);
GADGET_ITER_TARGET_MAP(dump_gpu_per_pid, gpu_per_pid);

SEC("iter/bpf_map_elem")
int dump_gpu_per_pid(struct bpf_iter__bpf_map_elem *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	__u32 *pidp = ctx->key;
	struct gpu_pid_metrics_aggregated *val = ctx->value;

	if (!pidp || !val)
		return 0;

	/* The bridge already filters pid 0 (NVML "unattributed" bucket),
	 * but defend in depth in case an older bridge writes it. */
	__u32 pid = *pidp;
	if (pid == 0)
		return 0;

	struct task_struct *task = bpf_task_from_pid((s32)pid);
	if (!task) {
		/* Process exited between the bridge's last poll and now.
		 * Skip rather than emit an event with comm="" and
		 * mntns_id=0 that would look like a host-namespace
		 * process to consumers. */
		return 0;
	}

	struct gpu_top_per_pid_event ev = {};

	ev.proc.pid = BPF_CORE_READ(task, tgid);
	ev.proc.tid = BPF_CORE_READ(task, pid);
	ev.proc.mntns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	bpf_probe_read_kernel_str(&ev.proc.comm, sizeof(ev.proc.comm),
				   BPF_CORE_READ(task, comm));
	ev.proc.creds.uid = BPF_CORE_READ(task, cred, uid.val);
	ev.proc.creds.gid = BPF_CORE_READ(task, cred, gid.val);

	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	if (parent) {
		ev.proc.parent.pid = BPF_CORE_READ(parent, tgid);
		ev.proc.parent.tid = BPF_CORE_READ(parent, pid);
		bpf_probe_read_kernel_str(&ev.proc.parent.comm,
					   sizeof(ev.proc.parent.comm),
					   BPF_CORE_READ(parent, comm));
	}

	bpf_task_release(task);

	ev.mem_used_raw       = val->used_gpu_memory_total;
	ev.sm_util_pct_max    = val->sm_util_pct_max;
	ev.mem_util_pct_max   = val->mem_util_pct_max;
	ev.gpu_device_primary = val->gpu_device_primary;
	ev.device_count       = val->device_count;
	ev.timestamp_ns       = val->timestamp_ns;

	bpf_seq_write(seq, &ev, sizeof(ev));
	return 0;
}

char __license[] SEC("license") = "GPL";
