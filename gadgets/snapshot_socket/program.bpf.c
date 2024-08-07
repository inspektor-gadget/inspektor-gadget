// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note

/* Copyright (c) 2021 The Inspektor Gadget authors */

/*
 * Inspired by the BPF selftests in the Linux tree:
 * https://github.com/torvalds/linux/blob/v5.13/tools/testing/selftests/bpf/progs/bpf_iter_tcp4.c
 */

/* This BPF program uses the GPL-restricted function bpf_seq_write(). */

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#include <gadget/macros.h>
#include <gadget/types.h>

#define AF_INET 2
#define AF_INET6 10

#define sk_v6_daddr __sk_common.skc_v6_daddr
#define sk_v6_rcv_saddr __sk_common.skc_v6_rcv_saddr

#define inet_daddr sk.__sk_common.skc_daddr
#define inet_rcv_saddr sk.__sk_common.skc_rcv_saddr
#define inet_dport sk.__sk_common.skc_dport

#define ir_loc_addr req.__req_common.skc_rcv_saddr
#define ir_num req.__req_common.skc_num
#define ir_rmt_addr req.__req_common.skc_daddr
#define ir_rmt_port req.__req_common.skc_dport
#define ir_v6_loc_addr req.__req_common.skc_v6_rcv_saddr
#define ir_v6_rmt_addr req.__req_common.skc_v6_daddr
#define ireq_family req.__req_common.skc_family

#define sk_family __sk_common.skc_family
#define sk_state __sk_common.skc_state
#define sk_proto __sk_common.sk_protocol

#define tw_daddr __tw_common.skc_daddr
#define tw_rcv_saddr __tw_common.skc_rcv_saddr
#define tw_dport __tw_common.skc_dport
#define tw_v6_daddr __tw_common.skc_v6_daddr
#define tw_v6_rcv_saddr __tw_common.skc_v6_rcv_saddr
#define tw_family __tw_common.skc_family

struct socket_entry {
	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;
	__u32 state;
	__u32 ino;
	gadget_netns_id netns_id;
};

GADGET_SNAPSHOTTER(sockets, socket_entry, ig_snap_tcp, ig_snap_udp);

/**
 * sock_i_ino - Returns the inode identifier associated to a socket.
 * @sk: The socket whom inode identifier will be returned.
 *
 * Returns the inode identifier corresponding to the given as parameter socket.
 *
 * Returns:
 * * The inode identifier associated to the socket.
 */
static unsigned long sock_i_ino(const struct sock *sk)
{
	const struct socket *sk_socket = sk->sk_socket;
	const struct inode *inode;
	unsigned long ino;

	if (!sk_socket)
		return 0;

	inode = &container_of(sk_socket, struct socket_alloc, socket)->vfs_inode;
	bpf_probe_read_kernel(&ino, sizeof(ino), &inode->i_ino);
	return ino;
}

/*
 * This function receives arguments as they are stored
 * in the different socket structure, i.e. network-byte order.
 */
static __always_inline void
socket_bpf_seq_write(struct seq_file *seq, __u16 family, __u16 proto,
		     __be32 src_v4, struct in6_addr *src_v6, __u16 srcp,
		     __be32 dest_v4, struct in6_addr *dest_v6, __u16 destp,
		     __u8 state, __u64 ino, __u32 netns)
{
	struct socket_entry entry = {};

	switch (family) {
	case AF_INET:
		entry.src.version = entry.dst.version = 4;
		entry.src.addr_raw.v4 = src_v4;
		entry.dst.addr_raw.v4 = dest_v4;
		break;
	case AF_INET6:
		entry.src.version = entry.dst.version = 6;
		bpf_probe_read_kernel(&entry.dst.addr_raw.v6,
				      sizeof(entry.dst.addr_raw.v6), dest_v6);
		bpf_probe_read_kernel(&entry.src.addr_raw.v6,
				      sizeof(entry.src.addr_raw.v6), src_v6);
		break;
	default:
		return;
	}

	entry.src.proto = entry.dst.proto = proto;
	entry.src.port = bpf_htons(srcp);
	entry.dst.port = bpf_htons(destp);
	entry.state = state;
	entry.ino = ino;
	entry.netns_id = netns;

	bpf_seq_write(seq, &entry, sizeof(entry));
}

static int dump_tcp_sock(struct seq_file *seq, __u32 netns, struct tcp_sock *tp)
{
	struct inet_connection_sock *icsk = &tp->inet_conn;
	struct inet_sock *inet = &icsk->icsk_inet;
	struct sock *sp = &inet->sk;

	socket_bpf_seq_write(seq, sp->sk_family, IPPROTO_TCP,
			     inet->inet_rcv_saddr, &sp->sk_v6_rcv_saddr,
			     inet->inet_sport, inet->inet_daddr,
			     &sp->sk_v6_daddr, inet->inet_dport, sp->sk_state,
			     sock_i_ino(sp), netns);

	return 0;
}

static int dump_tw_sock(struct seq_file *seq, __u32 netns,
			struct tcp_timewait_sock *ttw)
{
	struct inet_timewait_sock *tw = &ttw->tw_sk;

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

	socket_bpf_seq_write(seq, tw->tw_family, IPPROTO_TCP, tw->tw_rcv_saddr,
			     &tw->tw_v6_rcv_saddr, tw->tw_sport, tw->tw_daddr,
			     &tw->tw_v6_daddr, tw->tw_dport, tw->tw_substate, 0,
			     netns);

	return 0;
}

static int dump_req_sock(struct seq_file *seq, __u32 netns,
			 struct tcp_request_sock *treq)
{
	struct inet_request_sock *irsk = &treq->req;

	socket_bpf_seq_write(seq, irsk->ireq_family, IPPROTO_TCP,
			     irsk->ir_loc_addr, &irsk->ir_v6_loc_addr,
			     irsk->ir_num, irsk->ir_rmt_addr,
			     &irsk->ir_v6_rmt_addr, irsk->ir_rmt_port,
			     TCP_SYN_RECV, sock_i_ino(treq->req.req.sk), netns);

	return 0;
}

SEC("iter/tcp")
int ig_snap_tcp(struct bpf_iter__tcp *ctx)
{
	struct sock_common *sk_common = ctx->sk_common;
	struct seq_file *seq = ctx->meta->seq;
	struct tcp_timewait_sock *tw;
	struct tcp_request_sock *req;
	struct tcp_sock *tp;
	__u32 netns;

	if (sk_common == (void *)0)
		return 0;

	BPF_CORE_READ_INTO(&netns, sk_common, skc_net.net, ns.inum);

	tp = bpf_skc_to_tcp_sock(sk_common);
	if (tp)
		return dump_tcp_sock(seq, netns, tp);

	tw = bpf_skc_to_tcp_timewait_sock(sk_common);
	if (tw)
		return dump_tw_sock(seq, netns, tw);

	req = bpf_skc_to_tcp_request_sock(sk_common);
	if (req)
		return dump_req_sock(seq, netns, req);

	return 0;
}

SEC("iter/udp")
int ig_snap_udp(struct bpf_iter__udp *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct udp_sock *udp_sk = ctx->udp_sk;
	struct inet_sock *inet;
	struct sock *sp;

	if (udp_sk == (void *)0)
		return 0;

	inet = &udp_sk->inet;
	sp = &inet->sk;

	socket_bpf_seq_write(
		seq, sp->sk_family, IPPROTO_UDP, inet->inet_rcv_saddr,
		&sp->sk_v6_rcv_saddr, inet->inet_sport, inet->inet_daddr,
		&sp->sk_v6_daddr, inet->inet_dport, sp->sk_state,
		sock_i_ino(sp),
		BPF_CORE_READ(sp, __sk_common.skc_net.net, ns.inum));

	return 0;
}

char _license[] SEC("license") = "GPL";
