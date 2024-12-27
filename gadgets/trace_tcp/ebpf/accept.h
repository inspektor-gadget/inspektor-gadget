// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Microsoft Corporation
//
// Based on tcptracer(8) from BCC by Kinvolk GmbH and
// tcpconnect(8) by Anton Protopopov

#ifndef __IG_TCP_ACCEPT_H
#define __IG_TCP_ACCEPT_H

#include "common.h"

static __always_inline void handle_tcp_accept(struct pt_regs *ctx,
					      struct sock *sk)
{
	__u16 family;
	struct event *event;
	struct tuple_key_t t = {};

	if (!sk)
		return;

	if (filter_event(sk))
		return;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);

	fill_tuple(&t, sk, family);
	/* do not send event if IP address is 0.0.0.0 or port is 0 */
	if (is_ipv6_zero(&t.src) || is_ipv6_zero(&t.dst) || t.dst.port == 0 ||
	    t.src.port == 0)
		return;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return;

	fill_event(event, &t, accept);
	gadget_process_populate(&event->proc);

	gadget_submit_buf(ctx, &events, event, sizeof(*event));
}

#endif // __IG_TCP_ACCEPT_H
