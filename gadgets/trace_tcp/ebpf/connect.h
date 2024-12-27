// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Microsoft Corporation
//
// Based on tcptracer(8) from BCC by Kinvolk GmbH and
// tcpconnect(8) by Anton Protopopov

#ifndef __IG_TCP_CONNECT_H
#define __IG_TCP_CONNECT_H

#include "common.h"

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
	__type(key, u32);
	__type(value, struct sock *);
} sockets SEC(".maps");

static __always_inline int enter_tcp_connect(struct pt_regs *ctx,
					     struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = pid_tgid;

	if (filter_event(sk))
		return 0;

	bpf_map_update_elem(&sockets, &tid, &sk, 0);
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

	skpp = bpf_map_lookup_elem(&sockets, &tid);
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
	bpf_map_delete_elem(&sockets, &tid);
	return 0;
}

static __always_inline void handle_tcp_set_state(struct pt_regs *ctx,
						 struct sock *sk, int state)
{
	struct tuple_key_t tuple = {};
	struct event *event;
	__u16 family;

	if (state != TCP_ESTABLISHED && state != TCP_CLOSE)
		return;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);

	if (!fill_tuple(&tuple, sk, family))
		return;

	if (state == TCP_CLOSE)
		goto end;

	struct gadget_process *p;
	p = bpf_map_lookup_elem(&tuplepid, &tuple);
	if (!p)
		return; /* missed entry */

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		goto end;

	fill_event(event, &tuple, connect);
	__builtin_memcpy(&event->proc, p, sizeof(event->proc));

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

end:
	bpf_map_delete_elem(&tuplepid, &tuple);
}

#endif // __IG_TCP_CONNECT_H
