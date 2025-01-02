// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Microsoft Corporation
//
// Based on tcptracer(8) from BCC by Kinvolk GmbH and
// tcpconnect(8) by Anton Protopopov

#ifndef __IG_TCP_ACCEPT_H
#define __IG_TCP_ACCEPT_H

#include "common.h"

static __always_inline int handle_sys_accept_x(struct syscall_trace_exit *ctx)
{
	__u32 tid = bpf_get_current_pid_tgid();
	struct event *event;
	struct tuple_key_t t = {};
	struct sock **skpp;
	struct sock *sk;
	__u32 *fd_ptr;
	int fd = -1;
	__u16 family;

	fd_ptr = bpf_map_lookup_elem(&tcp_tid_fd, &tid);
	if (fd_ptr)
		fd = *fd_ptr;
	bpf_map_delete_elem(&tcp_tid_fd, &tid);

	skpp = bpf_map_lookup_elem(&tcp_tid_sock, &tid);
	if (!skpp)
		return 0;
	sk = *skpp;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);

	fill_tuple(&t, sk, family);
	/* do not send event if IP address is 0.0.0.0 or port is 0 */
	if (is_ipv6_zero(&t.src) || is_ipv6_zero(&t.dst) || t.dst.port == 0 ||
	    t.src.port == 0)
		goto end;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		goto end;

	fill_event(event, &t, NULL, 0, accept);
	event->fd = fd;

	if (ctx->ret >= 0)
		event->accept_fd = (int)ctx->ret;

	gadget_submit_buf(ctx, &events, event, sizeof(*event));
end:
	bpf_map_delete_elem(&tcp_tid_sock, &tid);

	return 0;
}

static __always_inline void handle_tcp_accept(struct pt_regs *ctx,
					      struct sock *sk)
{
	__u32 tid = bpf_get_current_pid_tgid();

	if (!sk)
		return;

	if (filter_event(sk, accept))
		return;

	bpf_map_update_elem(&tcp_tid_sock, &tid, &sk, 0);
}

#endif // __IG_TCP_ACCEPT_H
