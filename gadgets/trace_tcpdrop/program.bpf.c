// SPDX-License-Identifier: GPL-2.0
//
// Based on tcpdrop(8) from BCC
//
// Copyright 2018 Netflix, Inc.
// 30-May-2018    Brendan Gregg   Created this.
// 15-Jun-2022    Rong Tao        Add tracepoint:skb:kfree_skb
// Copyright 2023 Microsoft Corporation

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include <gadget/buffer.h>
#include <gadget/types.h>
#include <gadget/macros.h>

#define GADGET_TYPE_TRACING
#include <gadget/sockets-map.h>

#define TASK_COMM_LEN 16

// This enum is the same as the one in vmlinux.h, but redefined so that it can provide a name
// to be used for `state` in struct event. This way we get a readable value for column `state`.
enum tcp_state {
	tcp_established = 1,
	tcp_syn_sent = 2,
	tcp_syn_recv = 3,
	tcp_fin_wait1 = 4,
	tcp_fin_wait2 = 5,
	tcp_time_wait = 6,
	tcp_close = 7,
	tcp_close_wait = 8,
	tcp_last_ack = 9,
	tcp_listen = 10,
	tcp_closing = 11,
	tcp_new_syn_recv = 12,
	tcp_max_states = 13,
};

struct event {
	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;

	gadget_timestamp timestamp;
	enum tcp_state state;
	__u8 tcpflags;
	enum skb_drop_reason reason;
	__u32 netns;

	// The original gadget has instances of these fields for both process context and
	// socket context. Since sub-structures in the `event` are not yet supported, we only use
	// socket context for now. Once sub-structures in the `event` are supported, convert the
	// next fields to a struct.
	gadget_mntns_id mount_ns_id;
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 gid;
	__u8 task[TASK_COMM_LEN];
};

/* Define here, because there are conflicts with include files */
#define AF_INET 2
#define AF_INET6 10

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(tcpdrop, events, event);

// This struct is the same as struct tcphdr in vmlinux.h but with flags defined as single field instead of bitfield
struct tcphdr_with_flags {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u16 res1 : 4;
	__u16 doff : 4;
	__u8 flags;
	__be16 window;
	__sum16 check;
	__be16 urg_ptr;
};

static __always_inline int __trace_tcp_drop(void *ctx, struct sock *sk,
					    struct sk_buff *skb, int reason)
{
	if (sk == NULL)
		return 0;

	if (BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol) != IPPROTO_TCP)
		return 0;

	struct tcphdr_with_flags *tcphdr =
		(struct tcphdr_with_flags *)(BPF_CORE_READ(skb, head) +
					     BPF_CORE_READ(skb,
							   transport_header));
	struct inet_sock *sockp = (struct inet_sock *)sk;

	struct event *event;
	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	event->timestamp = bpf_ktime_get_boot_ns();
	event->state = BPF_CORE_READ(sk, __sk_common.skc_state);
	event->reason = reason;
	bpf_probe_read_kernel(&event->tcpflags, sizeof(event->tcpflags),
			      &tcphdr->flags);

	BPF_CORE_READ_INTO(&event->dst.port, sk, __sk_common.skc_dport);
	if (event->dst.port == 0)
		goto cleanup;

	BPF_CORE_READ_INTO(&event->src.port, sockp, inet_sport);
	if (event->src.port == 0)
		goto cleanup;

	unsigned int family = BPF_CORE_READ(sk, __sk_common.skc_family);
	switch (family) {
	case AF_INET:
		event->src.l3.version = event->dst.l3.version = 4;

		BPF_CORE_READ_INTO(&event->dst.l3.addr.v4, sk,
				   __sk_common.skc_daddr);
		if (event->dst.l3.addr.v4 == 0)
			goto cleanup;
		BPF_CORE_READ_INTO(&event->src.l3.addr.v4, sk,
				   __sk_common.skc_rcv_saddr);
		if (event->src.l3.addr.v4 == 0)
			goto cleanup;
		break;

	case AF_INET6:
		event->src.l3.version = event->dst.l3.version = 6;

		BPF_CORE_READ_INTO(
			&event->src.l3.addr.v6, sk,
			__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		if (event->src.l3.addr.v6 == 0)
			goto cleanup;
		BPF_CORE_READ_INTO(&event->dst.l3.addr.v6, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
		if (event->dst.l3.addr.v6 == 0)
			goto cleanup;
		break;

	default:
		// drop
		goto cleanup;
	}

	BPF_CORE_READ_INTO(&event->netns, sk, __sk_common.skc_net.net, ns.inum);
	struct sockets_value *skb_val = gadget_socket_lookup(sk, event->netns);
	if (skb_val != NULL) {
		event->mount_ns_id = skb_val->mntns;
		event->pid = skb_val->pid_tgid >> 32;
		event->tid = (__u32)skb_val->pid_tgid;
		__builtin_memcpy(&event->task, skb_val->task,
				 sizeof(event->task));
		event->uid = (__u32)skb_val->uid_gid;
		event->gid = (__u32)(skb_val->uid_gid >> 32);
	}

	gadget_submit_buf(ctx, &events, event, sizeof(*event));
	return 0;

cleanup:
	gadget_discard_buf(event);

	return 0;
}

SEC("tracepoint/skb/kfree_skb")
int ig_tcpdrop(struct trace_event_raw_kfree_skb *ctx)
{
	struct sk_buff *skb = ctx->skbaddr;
	struct sock *sk = BPF_CORE_READ(skb, sk);
	int reason = ctx->reason;

	// If bpf_core_enum_value fails, it will return 0 and that will not be a silent failure
	int reason_not_specified = bpf_core_enum_value(
		// Maybe reason type needs to be skb_drop_reason in the event struct
		enum skb_drop_reason, SKB_DROP_REASON_NOT_SPECIFIED);

	if (reason > reason_not_specified)
		return __trace_tcp_drop(ctx, sk, skb, reason);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
