// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 Microsoft Corporation

#ifndef __EBPF_COMMON_H
#define __EBPF_COMMON_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

/* The maximum number of items in maps */
#define MAX_ENTRIES 8192

enum event_type : u8 {
	connect,
	accept,
	close,
};

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;
	gadget_netns_id netns_id;

	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;

	enum event_type type_raw;
	gadget_errno error_raw;
};

struct tuple_key_t {
	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;
	u32 netns;
};

__u8 ip_v6_zero[16] = {
	0,
};

const volatile uid_t filter_uid = -1;
const volatile pid_t filter_pid = 0;
const volatile bool connect_only = false;

GADGET_PARAM(filter_uid);
GADGET_PARAM(filter_pid);
GADGET_PARAM(connect_only);

/* Define here, because there are conflicts with include files */
#define AF_INET 2
#define AF_INET6 10

// we need this to make sure the compiler doesn't remove our struct
const enum event_type unused_eventtype __attribute__((unused));

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(tracetcp, events, event);


/* returns true if the event should be skipped */
static __always_inline bool filter_event(struct sock *sk, __u32 uid, __u32 pid,
					 __u64 mntns_id, enum event_type type)
{
	u16 family;

	if (connect_only && type != connect)
		return true;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return true;

	if (gadget_should_discard_mntns_id(mntns_id))
		return true;

	if (filter_pid && pid != filter_pid)
		return true;

	if (filter_uid != (uid_t)-1 && uid != filter_uid)
		return true;

	return false;
}

static __always_inline bool fill_tuple(struct tuple_key_t *tuple,
				       struct sock *sk, int family)
{
	struct inet_sock *sockp = (struct inet_sock *)sk;

	BPF_CORE_READ_INTO(&tuple->netns, sk, __sk_common.skc_net.net, ns.inum);

	switch (family) {
	case AF_INET:
		BPF_CORE_READ_INTO(&tuple->src.addr_raw.v4, sk,
				   __sk_common.skc_rcv_saddr);
		if (tuple->src.addr_raw.v4 == 0)
			return false;

		BPF_CORE_READ_INTO(&tuple->dst.addr_raw.v4, sk,
				   __sk_common.skc_daddr);
		if (tuple->dst.addr_raw.v4 == 0)
			return false;

        tuple->src.version = tuple->dst.version = 4;
		break;
	case AF_INET6:
		BPF_CORE_READ_INTO(
			&tuple->src.addr_raw.v6, sk,
			__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		if (__builtin_memcmp(&tuple->src.addr_raw.v6, &ip_v6_zero,
				     sizeof(tuple->src.addr_raw.v6)) == 0)
			return false;
		BPF_CORE_READ_INTO(&tuple->dst.addr_raw.v6, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
		if (__builtin_memcmp(&tuple->dst.addr_raw.v6, &ip_v6_zero,
				     sizeof(tuple->dst.addr_raw.v6)) == 0)
			return false;

        tuple->src.version = tuple->dst.version = 6;
		break;
	/* it should not happen but to be sure let's handle this case */
	default:
		return false;
	}

	BPF_CORE_READ_INTO(&tuple->dst.port, sk, __sk_common.skc_dport);
	tuple->dst.port = bpf_ntohs(tuple->dst.port);
	if (tuple->dst.port == 0)
		return false;

	BPF_CORE_READ_INTO(&tuple->src.port, sockp, inet_sport);
	tuple->src.port = bpf_ntohs(tuple->src.port);
	if (tuple->src.port == 0)
		return false;

    tuple->src.proto_raw = tuple->dst.proto_raw = IPPROTO_TCP;

	return true;
}

static __always_inline void fill_event(struct event *event,
				       struct tuple_key_t *tuple, __u8 type)
{
	event->timestamp_raw = bpf_ktime_get_boot_ns();
	event->type_raw = type;
	event->src = tuple->src;
	event->dst = tuple->dst;
	event->netns_id = tuple->netns;
}


#endif // __EBPF_COMMON_H
