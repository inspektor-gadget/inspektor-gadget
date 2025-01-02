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

SEC("tracepoint/syscalls/sys_exit_connect")
int sys_connect_x(struct syscall_trace_exit *ctx)
{
	return handle_sys_connect_x(ctx);
}

SEC("kprobe/tcp_set_state")
int BPF_KPROBE(ig_tcp_state, struct sock *sk, int state)
{
	handle_tcp_set_state(ctx, sk, state);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int sys_connect_e(struct syscall_trace_enter *ctx)
{
	return update_tcp_tid_fd_map((__u32)ctx->args[0]);
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

SEC("tracepoint/syscalls/sys_enter_accept")
int sys_accept_e(struct syscall_trace_enter *ctx)
{
	return update_tcp_tid_fd_map((__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int sys_accept4_e(struct syscall_trace_enter *ctx)
{
	return update_tcp_tid_fd_map((__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_accept")
int sys_accept_x(struct syscall_trace_exit *ctx)
{
	return handle_sys_accept_x(ctx);
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int sys_accept4_x(struct syscall_trace_exit *ctx)
{
	return handle_sys_accept_x(ctx);
}

char LICENSE[] SEC("license") = "GPL";
