// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Francis Laniel <flaniel@linux.microsoft.com>

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/maps.bpf.h>
#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/core_fixes.bpf.h>

#define REQ_OP_BITS 8
#define REQ_OP_MASK ((1 << REQ_OP_BITS) - 1)

enum rw_type : u8 {
	read,
	write,
};

// for saving the timestamp and __data_len of each request
struct start_req_t {
	__u64 ts;
	__u64 data_len;
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
	__type(value, struct gadget_process);
} whobyreq SEC(".maps");

// the key for the output summary
struct info_t {
	struct gadget_process proc;
	enum rw_type rw_raw;
	int major;
	int minor;
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
	__type(key, struct info_t);
	__type(value, struct val_t);
} counts SEC(".maps");

GADGET_MAPITER(blockio, counts);

static __always_inline int trace_start(struct request *req)
{
	if (gadget_should_discard_data_current())
		return 0;

	struct gadget_process who;

	// cache PID and comm by-req
	gadget_process_populate(&who);

	bpf_map_update_elem(&whobyreq, &req, &who, 0);

	return 0;
}

SEC("kprobe/blk_mq_start_request")
int BPF_KPROBE(ig_topio_req, struct request *req)
{
	/* time block I/O */
	struct start_req_t start_req;
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
	unsigned int req_op_flags;
	struct gendisk *disk;
	struct gadget_process *whop;
	u64 delta_us;

	/* fetch timestamp and calculate delta */
	startp = bpf_map_lookup_elem(&start, &req);
	if (!startp)
		return 0; /* missed tracing issue */

	delta_us = (bpf_ktime_get_ns() - startp->ts) / 1000;

	/* setup info_t key */
	disk = get_disk(req);
	info.major = BPF_CORE_READ(disk, major);
	info.minor = BPF_CORE_READ(disk, first_minor);
	req_op_flags = BPF_CORE_READ(req, cmd_flags) & REQ_OP_MASK;
	if (req_op_flags == REQ_OP_WRITE)
		info.rw_raw = write;
	else if (req_op_flags == REQ_OP_READ)
		info.rw_raw = read;
	else
		goto end;

	whop = bpf_map_lookup_elem(&whobyreq, &req);
	if (whop)
		__builtin_memcpy(&info.proc, whop, sizeof(info.proc));

	valp = bpf_map_lookup_or_try_init(&counts, &info, &zero);

	if (valp) {
		/* save stats */
		valp->us += delta_us;
		valp->bytes += startp->data_len;
		valp->io++;
	}

end:
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
