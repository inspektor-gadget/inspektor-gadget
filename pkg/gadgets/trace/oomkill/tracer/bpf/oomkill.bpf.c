// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Jingxiang Zeng
// Copyright (c) 2022 Francis Laniel <flaniel@linux.microsoft.com>
#include <vmlinux/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "oomkill.h"
#include "mntns_filter.h"

// we need this to make sure the compiler doesn't remove our struct
const struct data_t *unuseddata __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("kprobe/oom_kill_process")
int BPF_KPROBE(ig_oom_kill, struct oom_control *oc, const char *message)
{
	struct data_t data;
	u64 mntns_id;
	u64 uid_gid = bpf_get_current_uid_gid();

	mntns_id = (u64) BPF_CORE_READ(oc, chosen, nsproxy, mnt_ns, ns.inum);

	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	data.fpid = bpf_get_current_pid_tgid() >> 32;
	data.fuid = (u32) uid_gid;
	data.fgid = (u32) (uid_gid >> 32);
	data.tpid = BPF_CORE_READ(oc, chosen, tgid);
	data.pages = BPF_CORE_READ(oc, totalpages);
	bpf_get_current_comm(&data.fcomm, sizeof(data.fcomm));
	bpf_probe_read_kernel(&data.tcomm, sizeof(data.tcomm), BPF_CORE_READ(oc, chosen, comm));
	data.mount_ns_id = mntns_id;
	data.timestamp = bpf_ktime_get_boot_ns();
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
