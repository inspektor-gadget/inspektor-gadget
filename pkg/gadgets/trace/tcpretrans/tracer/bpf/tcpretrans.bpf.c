// SPDX-License-Identifier: GPL-2.0
//
// Based on tcpretrans(8) from BCC
//
// Copyright 2016 Netflix, Inc.
//
// 14-Feb-2016   Brendan Gregg   Created this.
// 03-Nov-2017   Matthias Tafelmeier Extended this.
// Copyright 2023 Microsoft Corporation

#include <vmlinux/vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define GADGET_TYPE_TRACING
#include <sockets-map.h>

#include "tcpretrans.h"

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

static __always_inline int __trace_tcp_retrans(void *ctx, const struct sock *sk, const struct sk_buff *skb)
{
	struct inet_sock *sockp;
	struct task_struct *task;
	__u64 pid_tgid, uid_gid;
	struct event event = {};
	struct tcp_skb_cb *tcb;

	if (sk == NULL)
		return 0;

	if (BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol) != IPPROTO_TCP)
		return 0;

	sockp = (struct inet_sock *)sk;
	task = (struct task_struct*) bpf_get_current_task();
	pid_tgid = bpf_get_current_pid_tgid();
	uid_gid = bpf_get_current_uid_gid();

	event.timestamp = bpf_ktime_get_boot_ns();
	event.af = BPF_CORE_READ(sk, __sk_common.skc_family);
	event.state = BPF_CORE_READ(sk, __sk_common.skc_state);

	bpf_get_current_comm(&event.proc_current.task, sizeof(event.proc_current.task));
	event.proc_current.pid = pid_tgid >> 32;
	event.proc_current.tid = (__u32)pid_tgid;
	event.proc_current.mount_ns_id = (u64) BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	event.proc_current.uid = (u32) uid_gid;
	event.proc_current.gid = (u32) (uid_gid >> 32);

	// The tcp_retransmit_skb tracepoint is fired with a skb that does not
	// contain the TCP header because the TCP header is built on a cloned skb
	// we don't have access to.
	// skb->transport_header is not set: skb_transport_header_was_set() == false.
	// Instead, we have to read the TCP flags from the TCP control buffer.
	tcb = (struct tcp_skb_cb *)&(skb->cb[0]);
	bpf_probe_read_kernel(&event.tcpflags, sizeof(event.tcpflags), &tcb->tcp_flags);

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
		event.proc_socket.uid = (__u32) skb_val->uid_gid;
		event.proc_socket.gid = (__u32) (skb_val->uid_gid >> 32);
	}

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
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
