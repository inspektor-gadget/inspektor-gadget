// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note

/* Copyright (c) 2021 The Inspektor Gadget authors */

/*
 * Inspired by the BPF selftests in the Linux tree:
 * https://github.com/torvalds/linux/blob/v5.13/tools/testing/selftests/bpf/progs/bpf_iter_udp4.c
 */

/*
 * This BPF program uses the GPL-restricted function bpf_seq_printf().
 */

#include <vmlinux/vmlinux.h>

#include <bpf/bpf_helpers.h>
/*
 * libbpf v0.4.0 introduced BPF_SEQ_PRINTF in bpf_tracing.h.
 * In future versions, it will be in bpf_helpers.h.
 */
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "socket-common.h"

char _license[] SEC("license") = "GPL";

static const char proto[] = "UDP";

SEC("iter/udp")
int ig_snap_udp4(struct bpf_iter__udp *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct udp_sock *udp_sk = ctx->udp_sk;
	struct inet_sock *inet;

	if (udp_sk == (void *)0)
		return 0;

	inet = &udp_sk->inet;

	/* Filter out IPv6 for now */
	if (inet->sk.sk_family != AF_INET)
		return 0;

	socket_bpf_seq_print(seq, proto, inet->inet_rcv_saddr, inet->inet_sport,
			     inet->inet_daddr, inet->inet_dport,
			     inet->sk.sk_state, sock_i_ino(&inet->sk));

	return 0;
}
