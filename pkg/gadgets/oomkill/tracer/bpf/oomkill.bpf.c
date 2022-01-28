// SPDX-License-Identifier: GPL
/* Copyright (c) 2022 The Inspektor Gadget authors */
#include <linux/oom.h>
#include <vmlinux/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "oomkill.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(u32));
} mount_ns_set SEC(".maps");

const volatile bool filter_by_mnt_ns = false;

SEC("kprobe/oom_kill_process")
void BPF_KPROBE(oom_kill_process, struct oom_control *oc, const char *unused)
{
	struct task_struct *victim;
	struct event event = {};
	u64 mntns_id;

	victim = BPF_CORE_READ(oc, chosen);
	mntns_id = (u64) BPF_CORE_READ(victim, nsproxy, mnt_ns, ns.inum);

	if (filter_by_mnt_ns && !bpf_map_lookup_elem(&mount_ns_set, &mntns_id))
		return;

	event.tpid = bpf_get_current_pid_tgid() >> 32;
	event.kpid = BPF_CORE_READ(victim, tgid);
	event.pages = BPF_CORE_READ(oc, totalpages);
	bpf_get_current_comm(&event.tcomm, sizeof(event.tcomm));
	bpf_probe_read_kernel(&event.kcomm, sizeof(event.kcomm),
			      BPF_CORE_READ(victim, comm));
	event.mount_ns_id = mntns_id;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
			      sizeof(event));
}

/*
 * This eBPF core program is based on bcc oomkill BPF code from iovisor
 * oomkill.py file.
 * This file was under Apache-2.0 license, I would have liked to stick with this
 * to respect its history but I need to be able to call GPL-only functions.
 */
char _license[] SEC("license") = "GPL";
