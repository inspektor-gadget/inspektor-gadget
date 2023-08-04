// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note

/* Copyright (c) 2021 The Inspektor Gadget authors */

/*
 * Inspired by the BPF selftests in the Linux tree:
 * https://github.com/torvalds/linux/blob/v5.13/tools/testing/selftests/bpf/progs/bpf_iter_tcp4.c
 */

/*
 * This BPF program uses the GPL-restricted function bpf_seq_printf().
 */

#include <vmlinux/vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "socket-common.h"

char _license[] SEC("license") = "GPL";

static const char proto[] = "TCP";

static int dump_tcp_sock(struct seq_file *seq, struct tcp_sock *tp)
{
	const struct inet_connection_sock *icsk = &tp->inet_conn;
	const struct inet_sock *inet = &icsk->icsk_inet;
	const struct sock *sp = &inet->sk;

	socket_bpf_seq_print(seq, proto, inet->inet_rcv_saddr, inet->inet_sport,
			     inet->inet_daddr, inet->inet_dport, sp->sk_state,
			     sock_i_ino(sp));

	return 0;
}

static int dump_tw_sock(struct seq_file *seq, struct tcp_timewait_sock *ttw)
{
	struct inet_timewait_sock *tw = &ttw->tw_sk;

	socket_bpf_seq_print(seq, proto, tw->tw_rcv_saddr, tw->tw_sport,
			     tw->tw_daddr,
			     /*
		 * tcp_timewait_sock represents socket in TIME_WAIT state.
		 * Socket is this particular state are not associated with a
		 * struct sock:
		 * https://elixir.bootlin.com/linux/v5.15.12/source/include/linux/tcp.h#L442
		 * https://elixir.bootlin.com/linux/v5.15.12/source/include/net/inet_timewait_sock.h#L33
		 * Hence, they do not have an underlying file and, as a
		 * consequence, no inode.
		 *
		 * Like /proc/net/tcp, we print 0 as inode number for TIME_WAIT
		 * (state 6) socket:
		 * https://elixir.bootlin.com/linux/v5.15.12/source/include/net/tcp_states.h#L18
		 */
			     tw->tw_dport, tw->tw_substate, 0);

	return 0;
}

static int dump_req_sock(struct seq_file *seq, struct tcp_request_sock *treq)
{
	struct inet_request_sock *irsk = &treq->req;

	socket_bpf_seq_print(seq, proto, irsk->ir_loc_addr, irsk->ir_num,
			     irsk->ir_rmt_addr, irsk->ir_rmt_port, TCP_SYN_RECV,
			     sock_i_ino(treq->req.req.sk));

	return 0;
}

SEC("iter/tcp")
int ig_snap_tcp4(struct bpf_iter__tcp *ctx)
{
	struct sock_common *sk_common = ctx->sk_common;
	struct seq_file *seq = ctx->meta->seq;
	struct tcp_timewait_sock *tw;
	struct tcp_request_sock *req;
	struct tcp_sock *tp;

	if (sk_common == (void *)0)
		return 0;

	/* Filter out IPv6 for now */
	if (sk_common->skc_family != AF_INET)
		return 0;

	tp = bpf_skc_to_tcp_sock(sk_common);
	if (tp)
		return dump_tcp_sock(seq, tp);

	tw = bpf_skc_to_tcp_timewait_sock(sk_common);
	if (tw)
		return dump_tw_sock(seq, tw);

	req = bpf_skc_to_tcp_request_sock(sk_common);
	if (req)
		return dump_req_sock(seq, req);

	return 0;
}
