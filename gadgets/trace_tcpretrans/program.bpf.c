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

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/maps.bpf.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#define GADGET_TYPE_TRACING
#include <gadget/sockets-map.h>

enum type {
	RETRANS,
	LOSS,
};

enum tcp_flags_set : __u8 {
	FIN = 0x01,
	SYN = 0x02,
	RST = 0x04,
	PSH = 0x08,
	ACK = 0x10,
	URG = 0x20,
	ECE = 0x40,
	CWR = 0x80,
};

struct event {
	gadget_timestamp timestamp_raw;
	gadget_netns_id netns_id;
	gadget_mntns_id mntns_id;

	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;

	gadget_comm comm[TASK_COMM_LEN];
	// user-space terminology for pid and tid
	gadget_pid pid;
	gadget_tid tid;
	gadget_uid uid;
	gadget_gid gid;

	__u8 state;
	enum tcp_flags_set tcpflags_raw;
	__u32 reason;
	enum type type_raw;
};

/* Define here, because there are conflicts with include files */
#define AF_INET 2
#define AF_INET6 10

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(tcpretrans, events, event);

static __always_inline int __trace_tcp_retrans(void *ctx, const struct sock *sk,
					       const struct sk_buff *skb,
					       enum type type)
{
	struct inet_sock *sockp;
	struct tcp_skb_cb *tcb;
	struct event *event;
	unsigned int family;

	if (sk == NULL)
		return 0;

	if (BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol) != IPPROTO_TCP)
		return 0;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	event->src.proto_raw = event->dst.proto_raw = IPPROTO_TCP;

	sockp = (struct inet_sock *)sk;

	event->type_raw = type;
	event->timestamp_raw = bpf_ktime_get_boot_ns();

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	switch (family) {
	case AF_INET:
		event->src.version = event->dst.version = 4;

		BPF_CORE_READ_INTO(&event->src.addr_raw.v4, sk,
				   __sk_common.skc_rcv_saddr);
		if (event->src.addr_raw.v4 == 0)
			goto cleanup;

		BPF_CORE_READ_INTO(&event->dst.addr_raw.v4, sk,
				   __sk_common.skc_daddr);
		if (event->dst.addr_raw.v4 == 0)
			goto cleanup;
		break;

	case AF_INET6:
		event->src.version = event->dst.version = 6;

		BPF_CORE_READ_INTO(
			&event->src.addr_raw.v6, sk,
			__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		if (((u64 *)event->src.addr_raw.v6)[0] == 0 &&
		    ((u64 *)event->src.addr_raw.v6)[1] == 0)
			goto cleanup;

		BPF_CORE_READ_INTO(&event->dst.addr_raw.v6, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
		if (((u64 *)event->dst.addr_raw.v6)[0] == 0 &&
		    ((u64 *)event->dst.addr_raw.v6)[1] == 0)
			goto cleanup;
		break;

	default:
		// drop
		goto cleanup;
	}

	event->state = BPF_CORE_READ(sk, __sk_common.skc_state);

	// The tcp_retransmit_skb tracepoint is fired with a skb that does not
	// contain the TCP header because the TCP header is built on a cloned skb
	// we don't have access to.
	// skb->transport_header is not set: skb_transport_header_was_set() == false.
	// Instead, we have to read the TCP flags from the TCP control buffer.
	if (skb) {
		tcb = (struct tcp_skb_cb *)&(skb->cb[0]);
		bpf_probe_read_kernel(&event->tcpflags_raw,
				      sizeof(event->tcpflags_raw),
				      &tcb->tcp_flags);
	}

	BPF_CORE_READ_INTO(&event->dst.port, sk, __sk_common.skc_dport);
	event->dst.port = bpf_ntohs(
		event->dst.port); // host expects data in host byte order
	if (event->dst.port == 0)
		goto cleanup;

	BPF_CORE_READ_INTO(&event->src.port, sockp, inet_sport);
	event->src.port = bpf_ntohs(
		event->src.port); // host expects data in host byte order
	if (event->src.port == 0)
		goto cleanup;

	BPF_CORE_READ_INTO(&event->netns_id, sk, __sk_common.skc_net.net,
			   ns.inum);

	struct sockets_value *skb_val =
		gadget_socket_lookup(sk, event->netns_id);

	if (skb_val != NULL) {
		event->mntns_id = skb_val->mntns;
		// Use the mount namespace of the socket to filter by container
		if (gadget_should_discard_mntns_id(event->mntns_id))
			goto cleanup;

		event->pid = skb_val->pid_tgid >> 32;
		event->tid = (__u32)skb_val->pid_tgid;
		__builtin_memcpy(&event->comm, skb_val->task,
				 sizeof(event->comm));
		event->uid = (__u32)skb_val->uid_gid;
		event->gid = (__u32)(skb_val->uid_gid >> 32);
	}

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;

cleanup:
	gadget_discard_buf(event);

	return 0;
}

SEC("tracepoint/tcp/tcp_retransmit_skb")
int ig_tcpretrans(struct trace_event_raw_tcp_event_sk_skb *ctx)
{
	// struct trace_event_raw_tcp_event_sk_skb is described in:
	// /sys/kernel/tracing/events/tcp/tcp_retransmit_skb/format
	const struct sk_buff *skb = ctx->skbaddr;
	const struct sock *sk = ctx->skaddr;

	return __trace_tcp_retrans(ctx, sk, skb, RETRANS);
}

SEC("kprobe/tcp_send_loss_probe")
int BPF_KPROBE(ig_tcplossprobe, struct sock *sk)
{
	return __trace_tcp_retrans(ctx, sk, NULL, LOSS);
}

char LICENSE[] SEC("license") = "GPL";
