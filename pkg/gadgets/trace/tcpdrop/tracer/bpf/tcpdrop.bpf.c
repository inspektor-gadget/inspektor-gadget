// SPDX-License-Identifier: GPL-2.0
//
// Based on tcpdrop(8) from BCC
//
// Copyright 2018 Netflix, Inc.
// 30-May-2018    Brendan Gregg   Created this.
// 15-Jun-2022    Rong Tao        Add tracepoint:skb:kfree_skb
// Copyright 2023 Microsoft Corporation

#include <vmlinux/vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define GADGET_TYPE_TRACING
#include <sockets-map.h>

#include "tcpdrop.h"

/* Define here, because there are conflicts with include files */
#define AF_INET		2
#define AF_INET6	10

// we need this to make sure the compiler doesn't remove our struct
const struct event *unusedevent __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

// This struct is the same as struct tcphdr in vmlinux.h but with flags defined as single field instead of bitfield
struct tcphdr_with_flags {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u16 res1: 4;
	__u16 doff: 4;
	__u8 flags;
	__be16 window;
	__sum16 check;
	__be16 urg_ptr;
};

static __always_inline int __trace_tcp_drop(void *ctx, struct sock *sk, struct sk_buff *skb, int reason)
{
	if (sk == NULL)
		return 0;

	if (BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol) != IPPROTO_TCP)
		return 0;

	struct tcphdr_with_flags *tcphdr = (struct tcphdr_with_flags *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, transport_header));
	struct inet_sock *sockp = (struct inet_sock *)sk;
	struct task_struct *task = (struct task_struct*) bpf_get_current_task();
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	struct event event = {};
	event.timestamp = bpf_ktime_get_boot_ns();
	event.af = BPF_CORE_READ(sk, __sk_common.skc_family);
	event.state = BPF_CORE_READ(sk, __sk_common.skc_state);
	event.reason = reason;
	bpf_get_current_comm(&event.proc_current.task, sizeof(event.proc_current.task));
	event.proc_current.pid = pid_tgid >> 32;
	event.proc_current.tid = (__u32)pid_tgid;
	event.proc_current.mount_ns_id = (u64) BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	bpf_probe_read_kernel(&event.tcpflags, sizeof(event.tcpflags), &tcphdr->flags);

	BPF_CORE_READ_INTO(&event.dport, sk, __sk_common.skc_dport);
	if (event.dport == 0)
		return 0;

	BPF_CORE_READ_INTO(&event.sport, sockp, inet_sport);
	if (event.sport == 0)
		return 0;

	switch (event.af) {
	case AF_INET:
		BPF_CORE_READ_INTO(&event.daddr_v4, sk, __sk_common.skc_daddr);
		if (event.daddr_v4 == 0)
			return 0;
		BPF_CORE_READ_INTO(&event.saddr_v4, sk, __sk_common.skc_rcv_saddr);
		if (event.saddr_v4 == 0)
			return 0;
		break;

	case AF_INET6:
		BPF_CORE_READ_INTO(&event.saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		if (event.saddr_v6 == 0)
			return 0;
		BPF_CORE_READ_INTO(&event.daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
		if (event.daddr_v6 == 0)
			return 0;
		break;

	default:
		// drop
		return 0;
	}

	BPF_CORE_READ_INTO(&event.netns, sk, __sk_common.skc_net.net, ns.inum);
	struct sockets_value *skb_val = gadget_socket_lookup(sk, event.netns);
	if (skb_val != NULL) {
		event.proc_socket.mount_ns_id = skb_val->mntns;
		event.proc_socket.pid = skb_val->pid_tgid >> 32;
		event.proc_socket.tid = (__u32)skb_val->pid_tgid;
		__builtin_memcpy(&event.proc_socket.task,  skb_val->task, sizeof(event.proc_socket.task));
	}

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

SEC("tracepoint/skb/kfree_skb")
int ig_tcpdrop(struct trace_event_raw_kfree_skb *ctx)
{
	struct sk_buff *skb = ctx->skbaddr;
	struct sock *sk = BPF_CORE_READ(skb, sk);
	int reason = ctx->reason;

	// If bpf_core_enum_value fails, it will return 0 and that will not be a silent failure
	int reason_not_specified = bpf_core_enum_value(enum skb_drop_reason, SKB_DROP_REASON_NOT_SPECIFIED);

	if (reason > reason_not_specified)
		return __trace_tcp_drop(ctx, sk, skb, reason);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
