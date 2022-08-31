// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Jingxiang Zeng
// Copyright (c) 2022 Francis Laniel <flaniel@linux.microsoft.com>
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
} mount_ns_filter SEC(".maps");

const volatile bool filter_by_mnt_ns = false;

SEC("kprobe/oom_kill_process")
int BPF_KPROBE(ig_oom_kill, struct oom_control *oc, const char *message)
{
	struct data_t data;
	u64 mntns_id;

	mntns_id = (u64) BPF_CORE_READ(oc, chosen, nsproxy, mnt_ns, ns.inum);

	if (filter_by_mnt_ns && !bpf_map_lookup_elem(&mount_ns_filter, &mntns_id))
		return 0;

	data.fpid = bpf_get_current_pid_tgid() >> 32;
	data.tpid = BPF_CORE_READ(oc, chosen, tgid);
	data.pages = BPF_CORE_READ(oc, totalpages);
	bpf_get_current_comm(&data.fcomm, sizeof(data.fcomm));
	bpf_probe_read_kernel(&data.tcomm, sizeof(data.tcomm), BPF_CORE_READ(oc, chosen, comm));
	data.mount_ns_id = mntns_id;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
