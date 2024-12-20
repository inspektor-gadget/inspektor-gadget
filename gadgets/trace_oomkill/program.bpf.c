// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
// Copyright (c) 2020 Netflix

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#define TASK_COMM_LEN 16

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process fprocess;
	struct gadget_process tprocess;
	__u64 pages;
};

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(oomkill, events, event);

SEC("kprobe/oom_kill_process")
int BPF_KPROBE(ig_oom_kill, struct oom_control *oc, const char *message)
{
	struct event *event;
	u64 mntns_id;
	u64 uid_gid = bpf_get_current_uid_gid();

	mntns_id = (u64)BPF_CORE_READ(oc, chosen, nsproxy, mnt_ns, ns.inum);

	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	gadget_process_populate(&event->fprocess);
	event->tprocess.pid = BPF_CORE_READ(oc, chosen, tgid);
	bpf_probe_read_kernel(&event->tprocess.comm,
			      sizeof(event->tprocess.comm),
			      BPF_CORE_READ(oc, chosen, comm));
	event->tprocess.mntns_id = mntns_id;
	event->pages = BPF_CORE_READ(oc, totalpages);
	event->timestamp_raw = bpf_ktime_get_boot_ns();

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
