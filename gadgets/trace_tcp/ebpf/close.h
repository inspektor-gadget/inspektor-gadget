// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Microsoft Corporation
//
// Based on tcptracer(8) from BCC by Kinvolk GmbH and
// tcpconnect(8) by Anton Protopopov

#ifndef __IG_TCP_CLOSE_H
#define __IG_TCP_CLOSE_H

#include "common.h"

static __always_inline int handle_sys_close_e(struct syscall_trace_enter *ctx)
{
	__u32 fd = (__u32)ctx->args[0];
	__u32 tid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&tcp_tid_fd, &tid, &fd, 0);
	return 0;
}

static __always_inline int handle_sys_close_x(struct syscall_trace_exit *ctx)
{
	__u32 tid = bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&tcp_tid_fd, &tid);
	return 0;
}

static __always_inline void handle_tcp_close(struct pt_regs *ctx,
					     struct sock *sk)
{
	struct tuple_key_t tuple = {};
	struct event *event;
	u16 family;
	__u32 tid = bpf_get_current_pid_tgid();
	__u32 *fd;

	if (filter_event(sk, close))
		return;

	/*
	 * Don't generate close events for connections that were never
	 * established in the first place.
	 */
	u8 oldstate = BPF_CORE_READ(sk, __sk_common.skc_state);
	if (oldstate == TCP_SYN_SENT || oldstate == TCP_SYN_RECV ||
	    oldstate == TCP_NEW_SYN_RECV)
		return;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (!fill_tuple(&tuple, sk, family))
		return;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return;

	fill_event(event, &tuple, NULL, 0, close);
	event->new_fd = 0;

	fd = bpf_map_lookup_elem(&tcp_tid_fd, &tid);
	if (fd)
		event->fd = *fd;
	else
		event->fd = 0;

	gadget_submit_buf(ctx, &events, event, sizeof(*event));
}

#endif // __IG_TCP_CLOSE_H
