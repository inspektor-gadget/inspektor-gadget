// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Microsoft Corporation
//
// Based on tcptracer(8) from BCC by Kinvolk GmbH and
// tcpconnect(8) by Anton Protopopov

#ifndef __IG_TCP_ACCEPT_H
#define __IG_TCP_ACCEPT_H

#include "common.h"

static __always_inline int handle_sys_accept_e(struct syscall_trace_enter *ctx)
{
	__u32 fd = (__u32)ctx->args[0];
	__u32 tid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&tcp_tid_fd, &tid, &fd, 0);
	return 0;
}

static __always_inline int handle_sys_accept_x(struct syscall_trace_exit *ctx)
{
	__u32 tid = bpf_get_current_pid_tgid();
	struct event *event;
	struct tuple_key_t t = {};
	struct sock **skpp;
	struct sock *sk;
	__u32 *fdPtr;
	__u32 fd = 0;
	int ret = (int)ctx->ret; // Might be a error code or fd
	__u16 family;

	fdPtr = bpf_map_lookup_elem(&tcp_tid_fd, &tid);
	if (fdPtr)
		fd = *fdPtr;
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

	// --------------
	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		goto end;

	fill_event(event, &t, NULL, 0, accept);
	event->fd = fd;

	if (ret > 0)
		event->new_fd = ret;
	else
		event->new_fd = 0;

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
