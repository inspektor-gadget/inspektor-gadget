// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022-2024 Microsoft Corporation
//
// Based on tcptracer(8) from BCC by Kinvolk GmbH and
// tcpconnect(8) by Anton Protopopov

#ifndef __IG_TCP_CONNECT_H
#define __IG_TCP_CONNECT_H

#include "common.h"
#include <linux/errno.h>

struct extended_info {
	struct gadget_process proc;
	__u32 fd;
};

/*
 * Hash tuple->extended_info
 *
 * tcp_set_state doesn't run in the context of the process that initiated the
 * connection so we need to store a map TUPLE -> extended info to send the
 * right process information on the event.
 *
 * Entries are inserted in:
 * - kretprobe/tcp_v4_connect
 * - kretprobe/tcp_v6_connect
 *
 * Entries are deleted in a kprobe, so there are no kretprobe maxactive issues:
 * - kprobe/tcp_set_state
 */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct tuple_key_t);
	__type(value, struct extended_info);
} tuplepid SEC(".maps");

static __always_inline int enter_tcp_connect(struct pt_regs *ctx,
					     struct sock *sk)
{
	__u32 tid = bpf_get_current_pid_tgid();

	if (filter_event(sk, connect))
		return 0;

	bpf_map_update_elem(&tcp_tid_sock, &tid, &sk, 0);
	return 0;
}

static __always_inline int exit_tcp_connect(struct pt_regs *ctx, int ret,
					    __u16 family)
{
	__u32 tid;
	struct tuple_key_t tuple = {};
	struct extended_info ei = {};
	struct sock **skpp;
	struct sock *sk;
	__u32 *fd;

	if (ret)
		return 0;

	tid = bpf_get_current_pid_tgid();
	skpp = bpf_map_lookup_elem(&tcp_tid_sock, &tid);
	if (!skpp)
		return 0;

	fd = bpf_map_lookup_elem(&tcp_tid_fd, &tid);
	if (!fd)
		return 0;
	ei.fd = *fd;

	sk = *skpp;

	if (!fill_tuple(&tuple, sk, family))
		return 0;

	gadget_process_populate(&ei.proc);
	bpf_map_update_elem(&tuplepid, &tuple, &ei, 0);

	return 0;
}

static __always_inline int handle_sys_connect_x(struct syscall_trace_exit *ctx)
{
	// Clean up maps in tracepoint instead of kretprobe, so it is always
	// executed even when we reach the kretprobe maxactive limit.
	__u32 tid = bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&tcp_tid_sock, &tid);
	bpf_map_delete_elem(&tcp_tid_fd, &tid);
	return 0;
}

static __always_inline void handle_tcp_set_state(struct pt_regs *ctx,
						 struct sock *sk, int state)
{
	struct tuple_key_t tuple = {};
	struct event *event;
	struct extended_info *ei;
	__u16 family;
	int err = 0;
	int err = 0;

	// It would be nice if we can add a handler for TCP_SYN_SENT instead
	// of using kprobes on tcp_v4_connect and tcp_v6_connect
	// But when the state is set to TCP_SYN_SENT we may not have
	// the correct source port yet
	// https://elixir.bootlin.com/linux/v6.11.8/source/net/ipv4/tcp_ipv4.c#L301
	if (state != TCP_ESTABLISHED && state != TCP_CLOSE &&
	    state != TCP_SYN_SENT)
		return;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (!fill_tuple(&tuple, sk, family))
		return;

	ei = bpf_map_lookup_elem(&tuplepid, &tuple);
	if (!ei)
		return; /* missed entry */

	err = BPF_CORE_READ(sk, sk_err);

	// User does not want to see successful events
	if (failure_only && err == 0)
		goto end;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		goto end;

	// Explicitly capture error states
	if (state == TCP_CLOSE) {
		err = BPF_CORE_READ(sk, sk_err);
		if (err == 0)
			err = ETIMEDOUT; // Mark as timeout if no specific error
	}

	fill_event(event, &tuple, &ei->proc, err, connect);
	event->fd = ei->fd;

	gadget_submit_buf(ctx, &events, event, sizeof(*event));
end:
	bpf_map_delete_elem(&tuplepid, &tuple);
}

#endif // __IG_TCP_CONNECT_H
