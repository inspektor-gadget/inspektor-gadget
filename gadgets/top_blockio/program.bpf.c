// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Francis Laniel <flaniel@linux.microsoft.com>

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include <gadget/maps.bpf.h>
#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/core_fixes.bpf.h>
#include <gadget/mntns_filter.h>

#define REQ_OP_BITS 8
#define REQ_OP_MASK ((1 << REQ_OP_BITS) - 1)

#define TASK_COMM_LEN 16

enum rw_type : u8 {
	read,
	write,
};

// for saving the timestamp and __data_len of each request
struct start_req_t {
	__u64 ts;
	__u64 data_len;
};

// for saving process info by request
struct who_t {
	gadget_mntns_id mntns_id;
	__u32 pid;
	__u32 tid;
	char comm[TASK_COMM_LEN];
};

// the key for the output summary
struct info_t {
	gadget_mntns_id mntns_id;
	__u32 pid;
	__u32 tid;
	enum rw_type rw_raw;
	int major;
	int minor;
	char comm[TASK_COMM_LEN];
};

// the value of the output summary
struct val_t {
	__u64 bytes;
	__u64 us;
	__u32 io;
};

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

GADGET_MAPITER(blockio, counts);

static __always_inline int trace_start(struct request *req)
{
	__u64 mntns_id;
	__u64 pid_tgid;

	mntns_id = gadget_get_mntns_id();

	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	struct who_t who = {};

	// cache PID and comm by-req
	bpf_get_current_comm(&who.comm, sizeof(who.comm));
	pid_tgid = bpf_get_current_pid_tgid();
	who.pid = pid_tgid >> 32;
	who.tid = (__u32)pid_tgid;

	who.mntns_id = mntns_id;
	bpf_map_update_elem(&whobyreq, &req, &who, 0);

	return 0;
}

SEC("kprobe/blk_mq_start_request")
int BPF_KPROBE(ig_topio_req, struct request *req)
{
	/* time block I/O */
	struct start_req_t start_req;
	u64 mntns_id;

	mntns_id = gadget_get_mntns_id();

	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	start_req.ts = bpf_ktime_get_ns();
	start_req.data_len = BPF_CORE_READ(req, __data_len);

	bpf_map_update_elem(&start, &req, &start_req, 0);
	return 0;
}

static __always_inline int trace_done(struct request *req)
{
	struct val_t *valp, zero = {};
	struct info_t info = {};

	struct start_req_t *startp;
	unsigned int cmd_flags;
	struct gendisk *disk;
	struct who_t *whop;
	u64 delta_us;

	/* fetch timestamp and calculate delta */
	startp = bpf_map_lookup_elem(&start, &req);
	if (!startp)
		return 0; /* missed tracing issue */

	delta_us = (bpf_ktime_get_ns() - startp->ts) / 1000;

	/* setup info_t key */
	cmd_flags = BPF_CORE_READ(req, cmd_flags);

	disk = get_disk(req);
	info.major = BPF_CORE_READ(disk, major);
	info.minor = BPF_CORE_READ(disk, first_minor);
	if (!!((cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE)) {
		info.rw_raw = write;
	} else {
		info.rw_raw = read;
	}

	whop = bpf_map_lookup_elem(&whobyreq, &req);
	if (whop) {
		info.pid = whop->pid;
		info.tid = whop->tid;
		info.mntns_id = whop->mntns_id;
		__builtin_memcpy(&info.comm, whop->comm, sizeof(info.comm));
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

SEC("tp_btf/block_io_start")
int BPF_PROG(ig_topio_start, struct request *req)
{
	return trace_start(req);
}

SEC("tp_btf/block_io_done")
int BPF_PROG(ig_topio_done, struct request *req)
{
	return trace_done(req);
}

char LICENSE[] SEC("license") = "GPL";
