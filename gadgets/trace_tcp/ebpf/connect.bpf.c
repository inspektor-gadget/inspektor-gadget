// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 Microsoft Corporation

#include "common.h"
#include <linux/errno.h>

/*
 * tcp_set_state doesn't run in the context of the process that initiated the
 * connection so we need to store a map TUPLE -> PID to send the right PID on
 * the event.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct tuple_key_t);
	__type(value, struct gadget_process);
} tuplepid SEC(".maps");

/*
 * We store the socket pointer in a map to be able to retrieve it in the
 * kretprobe.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // tid
	__type(value, struct sock *);
} tcp_connect_ctx SEC(".maps");

static __always_inline int enter_tcp_connect(struct pt_regs *ctx,
					     struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = pid_tgid;
	__u64 uid_gid = bpf_get_current_uid_gid();
	__u32 uid = uid_gid;
	__u64 mntns_id;

	mntns_id = gadget_get_mntns_id();

	if (filter_event(sk, uid, pid, mntns_id, connect))
		return 0;

	bpf_map_update_elem(&tcp_connect_ctx, &tid, &sk, 0);
	return 0;
}

static __always_inline int exit_tcp_connect(struct pt_regs *ctx, int ret,
					    __u16 family)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = pid_tgid;
	struct tuple_key_t tuple = {};
	struct gadget_process proc = {};
	struct sock **skpp;
	struct sock *sk;

	skpp = bpf_map_lookup_elem(&tcp_connect_ctx, &tid);
	if (!skpp)
		return 0;

	if (ret)
		goto end;

	sk = *skpp;

	if (!fill_tuple(&tuple, sk, family))
		goto end;

	gadget_process_populate(&proc);
	bpf_map_update_elem(&tuplepid, &tuple, &proc, 0);

end:
	bpf_map_delete_elem(&tcp_connect_ctx, &tid);
	return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(ig_tcp_v4_co_e, struct sock *sk)
{
	return enter_tcp_connect(ctx, sk);
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(ig_tcp_v4_co_x, int ret)
{
	return exit_tcp_connect(ctx, ret, AF_INET);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(ig_tcp_v6_co_e, struct sock *sk)
{
	return enter_tcp_connect(ctx, sk);
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(ig_tcp_v6_co_x, int ret)
{
	return exit_tcp_connect(ctx, ret, AF_INET6);
}

static __always_inline void handleEstablishedAndClose(void *ctx,
						      struct sock *sk)
{
	struct tuple_key_t tuple = {};
	struct event *event;
	struct gadget_process *p;
	__u16 family;
	int err;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (!fill_tuple(&tuple, sk, family))
		return;

	p = bpf_map_lookup_elem(&tuplepid, &tuple);
	if (!p)
		return;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		goto end;

	err = BPF_CORE_READ(sk, sk_err);

	fill_event(event, &tuple, connect);
	event->proc = *p;
	event->error_raw = err;

	gadget_submit_buf(ctx, &events, event, sizeof(*event));
end:
	bpf_map_delete_elem(&tuplepid, &tuple);
}

SEC("kprobe/tcp_set_state")
int BPF_KPROBE(ig_tcp_state, struct sock *sk, int state)
{
	// It would be nice if we can a handler for TCP_SYN_SENT instead
	// of using kprobes on tcp_v4_connect and tcp_v6_connect
	// But when the state is set to TCP_SYN_SENT we may not have
	// the correct source port yet
	// https://elixir.bootlin.com/linux/v6.11.8/source/net/ipv4/tcp_ipv4.c#L301
	if (state == TCP_ESTABLISHED || state == TCP_CLOSE)
		handleEstablishedAndClose(ctx, sk);
	return 0;
}
