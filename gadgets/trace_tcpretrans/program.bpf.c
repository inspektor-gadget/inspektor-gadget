// SPDX-License-Identifier: GPL-2.0
//
// Based on tcpretrans(8) from BCC
//
// Copyright 2016 Netflix, Inc.
//
// 14-Feb-2016   Brendan Gregg   Created this.
// 03-Nov-2017   Matthias Tafelmeier Extended this.
// Copyright 2023 Microsoft Corporation

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include <gadget/macros.h>
#include <gadget/maps.bpf.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#define GADGET_TYPE_TRACING
#include <gadget/sockets-map.h>

#define TASK_COMM_LEN 16

struct event {
	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;

	__u64 timestamp;
	__u8 state;
	__u8 tcpflags;
	__u32 reason;
	__u32 netns;

	mnt_ns_id_t mntns_id;
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 gid;
	__u8 task[TASK_COMM_LEN];
};

/* Define here, because there are conflicts with include files */
#define AF_INET 2
#define AF_INET6 10

// we need this to make sure the compiler doesn't remove our struct
const struct event *unusedevent __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__type(value, struct event);
} events SEC(".maps");

GADGET_TRACE_MAP(events);

static __always_inline int __trace_tcp_retrans(void *ctx, const struct sock *sk,
					       const struct sk_buff *skb)
{
	struct inet_sock *sockp;
	struct event event = {};
	struct tcp_skb_cb *tcb;
	unsigned int family;

	if (sk == NULL)
		return 0;

	if (BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol) != IPPROTO_TCP)
		return 0;
	event.src.proto = event.dst.proto = IPPROTO_TCP;

	sockp = (struct inet_sock *)sk;

	event.timestamp = bpf_ktime_get_boot_ns();

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	switch (family) {
	case AF_INET:
		event.src.l3.version = event.dst.l3.version = 4;

		BPF_CORE_READ_INTO(&event.src.l3.addr.v4, sk,
				   __sk_common.skc_rcv_saddr);
		if (event.src.l3.addr.v4 == 0)
			return 0;

		BPF_CORE_READ_INTO(&event.dst.l3.addr.v4, sk,
				   __sk_common.skc_daddr);
		if (event.dst.l3.addr.v4 == 0)
			return 0;
		break;

	case AF_INET6:
		event.src.l3.version = event.dst.l3.version = 6;

		BPF_CORE_READ_INTO(
			&event.src.l3.addr.v6, sk,
			__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		if (((u64 *)event.src.l3.addr.v6)[0] == 0 &&
		    ((u64 *)event.src.l3.addr.v6)[1] == 0)
			return 0;

		BPF_CORE_READ_INTO(&event.dst.l3.addr.v6, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
		if (((u64 *)event.dst.l3.addr.v6)[0] == 0 &&
		    ((u64 *)event.dst.l3.addr.v6)[1] == 0)
			return 0;
		break;

	default:
		// drop
		return 0;
	}

	event.state = BPF_CORE_READ(sk, __sk_common.skc_state);

	// The tcp_retransmit_skb tracepoint is fired with a skb that does not
	// contain the TCP header because the TCP header is built on a cloned skb
	// we don't have access to.
	// skb->transport_header is not set: skb_transport_header_was_set() == false.
	// Instead, we have to read the TCP flags from the TCP control buffer.
	tcb = (struct tcp_skb_cb *)&(skb->cb[0]);
	bpf_probe_read_kernel(&event.tcpflags, sizeof(event.tcpflags),
			      &tcb->tcp_flags);

	BPF_CORE_READ_INTO(&event.dst.port, sk, __sk_common.skc_dport);
	event.dst.port = bpf_ntohs(
		event.dst.port); // host expects data in host byte order
	if (event.dst.port == 0)
		return 0;

	BPF_CORE_READ_INTO(&event.src.port, sockp, inet_sport);
	event.src.port = bpf_ntohs(
		event.src.port); // host expects data in host byte order
	if (event.src.port == 0)
		return 0;

	BPF_CORE_READ_INTO(&event.netns, sk, __sk_common.skc_net.net, ns.inum);

	struct sockets_value *skb_val = gadget_socket_lookup(sk, event.netns);

	if (skb_val != NULL) {
		event.mntns_id = skb_val->mntns;
		// Use the mount namespace of the socket to filter by container
		if (gadget_should_discard_mntns_id(event.mntns_id))
			return 0;

		event.pid = skb_val->pid_tgid >> 32;
		event.tid = (__u32)skb_val->pid_tgid;
		__builtin_memcpy(&event.task, skb_val->task,
				 sizeof(event.task));
		event.uid = (__u32)skb_val->uid_gid;
		event.gid = (__u32)(skb_val->uid_gid >> 32);
	}

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
			      sizeof(event));
	return 0;
}

SEC("tracepoint/tcp/tcp_retransmit_skb")
int ig_tcpretrans(struct trace_event_raw_tcp_event_sk_skb *ctx)
{
	// struct trace_event_raw_tcp_event_sk_skb is described in:
	// /sys/kernel/tracing/events/tcp/tcp_retransmit_skb/format
	const struct sk_buff *skb = ctx->skbaddr;
	const struct sock *sk = ctx->skaddr;

	return __trace_tcp_retrans(ctx, sk, skb);
}

char LICENSE[] SEC("license") = "GPL";
