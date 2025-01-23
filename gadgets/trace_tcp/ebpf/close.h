// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Microsoft Corporation
//
// Based on tcptracer(8) from BCC by Kinvolk GmbH and
// tcpconnect(8) by Anton Protopopov

#ifndef __IG_TCP_CLOSE_H
#define __IG_TCP_CLOSE_H

#include "common.h"

static __always_inline void handle_tcp_close(struct pt_regs *ctx,
					     struct sock *sk)
{
	struct tuple_key_t tuple = {};
	struct event *event;
	u16 family;

	// Close events don't have errors.
	// User does not want to see successful events.
	if (failure_only)
		return;

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

	gadget_submit_buf(ctx, &events, event, sizeof(*event));
}

#endif // __IG_TCP_CLOSE_H
