// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Francis Laniel <flaniel@linux.microsoft.com>
#include <vmlinux/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "biotop.h"
#include "maps.bpf.h"

const volatile bool filter_by_mnt_ns = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct request *);
	__type(value, struct start_req_t);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct request *);
	__type(value, struct who_t);
} whobyreq SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct info_t);
	__type(value, struct val_t);
} counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(u32));
} mount_ns_filter SEC(".maps");

SEC("kprobe/blk_account_io_start")
int BPF_KPROBE(ig_topio_start, struct request *req)
{
	struct task_struct *task;
	u64 mntns_id;

	task = (struct task_struct*) bpf_get_current_task();
	mntns_id = (u64) BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

	if (filter_by_mnt_ns && !bpf_map_lookup_elem(&mount_ns_filter, &mntns_id))
		return 0;

	struct who_t who = {};

	// cache PID and comm by-req
	bpf_get_current_comm(&who.name, sizeof(who.name));
	who.pid = bpf_get_current_pid_tgid() >> 32;
	who.mntnsid = mntns_id;
	bpf_map_update_elem(&whobyreq, &req, &who, 0);

	return 0;
}

SEC("kprobe/blk_mq_start_request")
int BPF_KPROBE(ig_topio_req, struct request *req)
{
	/* time block I/O */
	struct start_req_t start_req;
	struct task_struct *task;
	u64 mntns_id;

	task = (struct task_struct*) bpf_get_current_task();
	mntns_id = (u64) BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

	if (filter_by_mnt_ns && !bpf_map_lookup_elem(&mount_ns_filter, &mntns_id))
		return 0;

	start_req.ts = bpf_ktime_get_ns();
	start_req.data_len = BPF_CORE_READ(req, __data_len);

	bpf_map_update_elem(&start, &req, &start_req, 0);
	return 0;
}

SEC("kprobe/blk_account_io_done")
int BPF_KPROBE(ig_topio_done, struct request *req, u64 now)
{
	struct val_t *valp, zero = {};
	struct info_t info = {};

	struct start_req_t *startp;
	unsigned int cmd_flags;
	struct who_t *whop;
	u64 delta_us;

	/* fetch timestamp and calculate delta */
	startp = bpf_map_lookup_elem(&start, &req);
	if (!startp)
		return 0;    /* missed tracing issue */

	delta_us = (bpf_ktime_get_ns() - startp->ts) / 1000;

	/* setup info_t key */
	cmd_flags = BPF_CORE_READ(req, cmd_flags);

	info.major = BPF_CORE_READ(req, rq_disk, major);
	info.minor = BPF_CORE_READ(req, rq_disk, first_minor);
	info.rwflag = !!((cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);

	whop = bpf_map_lookup_elem(&whobyreq, &req);
	if (whop) {
		info.pid = whop->pid;
		info.mntnsid = whop->mntnsid;
		__builtin_memcpy(&info.name, whop->name, sizeof(info.name));
	}

	valp = bpf_map_lookup_or_try_init(&counts, &info, &zero);

	if (valp) {
		/* save stats */
		valp->us += delta_us;
		valp->bytes += startp->data_len;
		valp->io++;
	}

	bpf_map_delete_elem(&start, &req);
	bpf_map_delete_elem(&whobyreq, &req);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
