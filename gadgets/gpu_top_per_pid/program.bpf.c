// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 The Inspektor Gadget authors */

/*
 * gpu_top_per_pid: report current per-process GPU usage from the
 * gpu-ebpf-bridge daemon.
 *
 * Companion gadget to gpu_top. Where gpu_top iterates the bridge's
 * per-device map, this iterates all live tasks in the kernel via
 * SEC("iter/task") and, for those whose tgid appears in the bridge's
 * per-PID map (gpu_per_pid), emits one event per PID with its GPU
 * memory and peak utilization across all devices.
 *
 * Each event carries a struct gadget_process so IG's container, pod,
 * and K8s enrichers add the runtime context automatically from the
 * mntns_id field — no extra plumbing in this gadget.
 *
 * Design note: an earlier revision iterated gpu_per_pid directly via
 * SEC("iter/bpf_map_elem") and looked up the task by PID with
 * bpf_task_from_pid. That kfunc was added in Linux 6.2 (commit
 * 3f0e6f2b41d3, 2022-11-22) but AKS default node pools ship 5.15 as
 * of 2026-Q3, so we invert the direction: iterate all tasks (walking
 * a few thousand PIDs is cheap) and short-circuit on
 * bpf_map_lookup_elem(gpu_per_pid). Works on kernels 5.8+.
 *
 * Struct gpu_pid_metrics_aggregated is copied verbatim from
 * include/gpu_types.h (GPU_SCHEMA_VERSION 1).
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include <gadget/macros.h>
#include <gadget/types.h>

#define GPU_BRIDGE_WANT_PER_PID
#include <gadget/gpu_bridge_maps.h>

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

	__u8 gpu_device_primary;
	__u8 device_count;
	__u16 _pad;

	__u64 timestamp_ns;
};

GADGET_ITER(gpu_top_per_pid, gpu_top_per_pid_event, dump_gpu_per_pid);

SEC("iter/task")
int dump_gpu_per_pid(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;

	if (task == NULL)
		return 0;

	/* Only look at main threads; gpu_per_pid is keyed by tgid.
	 * Also filters out the sentinel entry the iter emits at the end
	 * of the walk (task == NULL is handled above; task->tgid == 0
	 * is the swapper). */
	__u32 tgid = BPF_CORE_READ(task, tgid);
	__u32 pid = BPF_CORE_READ(task, pid);
	if (tgid == 0 || pid != tgid)
		return 0;

	struct gpu_pid_metrics_aggregated *val =
		bpf_map_lookup_elem(&gpu_per_pid, &tgid);
	if (!val)
		return 0;
	if (val->used_gpu_memory_total == 0)
		return 0;

	struct gpu_top_per_pid_event ev;
	__builtin_memset(&ev, 0, sizeof(ev));

	ev.proc.pid = tgid;
	ev.proc.tid = pid;
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

	ev.mem_used_raw = val->used_gpu_memory_total;
	ev.sm_util_pct_max = val->sm_util_pct_max;
	ev.mem_util_pct_max = val->mem_util_pct_max;
	ev.gpu_device_primary = val->gpu_device_primary;
	ev.device_count = val->device_count;
	ev.timestamp_ns = val->timestamp_ns;

	bpf_seq_write(seq, &ev, sizeof(ev));
	return 0;
}

char __license[] SEC("license") = "GPL";
