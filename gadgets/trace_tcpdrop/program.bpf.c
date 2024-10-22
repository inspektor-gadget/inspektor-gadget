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
#include <gadget/core_fixes.bpf.h>
#include <gadget/kernel_stack_map.h>

#define GADGET_TYPE_TRACING
#include <gadget/sockets-map.h>

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

	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;

	// The original gadget has instances of these fields for both process context and
	// socket context. Since sub-structures in the `event` are not yet supported, we only use
	// socket context for now. Once sub-structures in the `event` are supported, convert the
	// next fields to a struct.
	gadget_mntns_id mount_ns_id;
	gadget_comm comm[TASK_COMM_LEN];
	// user-space terminology for pid and tid
	gadget_pid pid;
	gadget_tid tid;
	gadget_uid uid;
	gadget_gid gid;

	enum tcp_state state_raw;
	enum tcp_flags_set tcpflags_raw;
	enum skb_drop_reason reason_raw;
	gadget_kernel_stack kernel_stack_raw;
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

	event->timestamp_raw = bpf_ktime_get_boot_ns();
	event->state_raw = BPF_CORE_READ(sk, __sk_common.skc_state);
	event->reason_raw = reason;
	event->kernel_stack_raw = gadget_get_kernel_stack(ctx);
	bpf_probe_read_kernel(&event->tcpflags_raw, sizeof(event->tcpflags_raw),
			      &tcphdr->flags);

	event->dst.port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (event->dst.port == 0)
		goto cleanup;

	event->src.port = bpf_ntohs(BPF_CORE_READ(sockp, inet_sport));
	if (event->src.port == 0)
		goto cleanup;

	unsigned int family = BPF_CORE_READ(sk, __sk_common.skc_family);
	switch (family) {
	case AF_INET:
		event->src.version = event->dst.version = 4;

		BPF_CORE_READ_INTO(&event->dst.addr_raw.v4, sk,
				   __sk_common.skc_daddr);
		if (event->dst.addr_raw.v4 == 0)
			goto cleanup;
		BPF_CORE_READ_INTO(&event->src.addr_raw.v4, sk,
				   __sk_common.skc_rcv_saddr);
		if (event->src.addr_raw.v4 == 0)
			goto cleanup;
		break;

	case AF_INET6:
		event->src.version = event->dst.version = 6;

		BPF_CORE_READ_INTO(
			&event->src.addr_raw.v6, sk,
			__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		if (event->src.addr_raw.v6 == 0)
			goto cleanup;
		BPF_CORE_READ_INTO(&event->dst.addr_raw.v6, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
		if (event->dst.addr_raw.v6 == 0)
			goto cleanup;
		break;

	default:
		// drop
		goto cleanup;
	}

	BPF_CORE_READ_INTO(&event->netns_id, sk, __sk_common.skc_net.net,
			   ns.inum);
	struct sockets_value *skb_val =
		gadget_socket_lookup(sk, event->netns_id);
	if (skb_val != NULL) {
		event->mount_ns_id = skb_val->mntns;
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

SEC("tracepoint/skb/kfree_skb")
int ig_tcpdrop(struct trace_event_raw_kfree_skb *ctx)
{
	struct sk_buff *skb = ctx->skbaddr;
	struct sock *sk = BPF_CORE_READ(skb, sk);
	int reason = ctx->reason;

	// If enum value was not found, bpf_core_enum_value returns 0.
	// The verifier will reject the program with
	// invalid func unknown#195896080
	// 195896080 == 0xbad2310 reads "bad relo"
	int reason_not_specified = bpf_core_enum_value(
		enum skb_drop_reason, SKB_DROP_REASON_NOT_SPECIFIED);
	if (reason_not_specified == 0)
		bpf_core_unreachable();

	if (reason > reason_not_specified)
		return __trace_tcp_drop(ctx, sk, skb, reason);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
