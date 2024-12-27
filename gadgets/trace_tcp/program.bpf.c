// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Microsoft Corporation
//
// Based on tcptracer(8) from BCC by Kinvolk GmbH and
// tcpconnect(8) by Anton Protopopov

#include "ebpf/accept.h"
#include "ebpf/close.h"
#include "ebpf/connect.h"
#include "ebpf/common.h"

// kprobes for TCP connect events

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(ig_tcp_v4_co_e, struct sock *sk)
{
	return enter_tcp_connect(ctx, sk);
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(ig_tcp_v4_co_x, int ret)
{
	return exit_tcp_connect(ctx, ret, AF_INET);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(ig_tcp_v6_co_e, struct sock *sk)
{
	return enter_tcp_connect(ctx, sk);
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(ig_tcp_v6_co_x, int ret)
{
	return exit_tcp_connect(ctx, ret, AF_INET6);
}

SEC("kprobe/tcp_set_state")
int BPF_KPROBE(ig_tcp_state, struct sock *sk, int state)
{
	handle_tcp_set_state(ctx, sk, state);
	return 0;
}

// kprobe for TCP close events

SEC("kprobe/tcp_close")
int BPF_KPROBE(ig_tcp_close, struct sock *sk)
{
	handle_tcp_close(ctx, sk);
	return 0;
}

// kprobe for TCP accept events

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(ig_tcp_accept, struct sock *sk)
{
	handle_tcp_accept(ctx, sk);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
