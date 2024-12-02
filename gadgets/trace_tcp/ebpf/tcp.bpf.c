// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Microsoft Corporation
//
// Based on tcptracer(8) from BCC by Kinvolk GmbH and
// tcpconnect(8) by Anton Protopopov

#include "common.h"

SEC("kprobe/tcp_close")
int BPF_KPROBE(ig_tcp_close, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u64 uid_gid = bpf_get_current_uid_gid();
	__u32 uid = uid_gid;
	struct tuple_key_t tuple = {};
	struct event *event;
	u16 family;
	__u64 mntns_id;

	mntns_id = gadget_get_mntns_id();

	if (filter_event(sk, uid, pid, mntns_id, close))
		return 0;

	/*
	 * Don't generate close events for connections that were never
	 * established in the first place.
	 */
	u8 oldstate = BPF_CORE_READ(sk, __sk_common.skc_state);
	if (oldstate == TCP_SYN_SENT || oldstate == TCP_SYN_RECV ||
	    oldstate == TCP_NEW_SYN_RECV)
		return 0;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (!fill_tuple(&tuple, sk, family))
		return 0;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	fill_event(event, &tuple, close);
	gadget_process_populate(&event->proc);

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
};

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(ig_tcp_accept, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u64 uid_gid = bpf_get_current_uid_gid();
	__u32 uid = uid_gid;
	__u16 family;
	struct event *event;
	struct tuple_key_t t = {};
	u64 mntns_id;

	if (!sk)
		return 0;

	mntns_id = gadget_get_mntns_id();

	if (filter_event(sk, uid, pid, mntns_id, accept))
		return 0;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);

	fill_tuple(&t, sk, family);
	/* do not send event if IP address is 0.0.0.0 or port is 0 */
	if (__builtin_memcmp(t.src.addr_raw.v6, ip_v6_zero,
			     sizeof(t.src.addr_raw.v6)) == 0 ||
	    __builtin_memcmp(t.dst.addr_raw.v6, ip_v6_zero,
			     sizeof(t.dst.addr_raw.v6)) == 0 ||
	    t.dst.port == 0 || t.src.port == 0)
		return 0;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	fill_event(event, &t, accept);
	gadget_process_populate(&event->proc);

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}
