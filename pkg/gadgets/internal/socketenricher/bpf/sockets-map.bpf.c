// SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0
/* Copyright (c) 2021 The Inspektor Gadget authors */

#include <vmlinux/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include <bpf/bpf_helpers.h>

#define SOCKETS_MAP_IMPLEMENTATION
#include "sockets-map.h"

#define MAX_ENTRIES	10240

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, void *);
} start SEC(".maps");

static __always_inline int
probe_bind_entry(struct pt_regs *ctx, struct socket *socket)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	bpf_map_update_elem(&start, &pid_tgid, &socket, BPF_ANY);
	return 0;
};

static __always_inline int
probe_bind_exit(struct pt_regs *ctx, short ver)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct task_struct *task;
	struct socket **socketp, *socket;
	struct inet_sock *inet_sock;
	struct sock *sock;
	__u16 sport = 0;
	int ret;

	socketp = bpf_map_lookup_elem(&start, &pid_tgid);
	if (!socketp)
		return 0;

	ret = PT_REGS_RC(ctx);
	if (ret != 0)
		goto cleanup;

	socket = *socketp;
	sock = BPF_CORE_READ(socket, sk);
	inet_sock = (struct inet_sock *)sock;

	struct sockets_key socket_key = {0,};

	BPF_CORE_READ_INTO(&socket_key.netns, sock, __sk_common.skc_net.net, ns.inum);

	socket_key.proto = BPF_CORE_READ_BITFIELD_PROBED(sock, sk_protocol);
	socket_key.port = bpf_ntohs(BPF_CORE_READ(inet_sock, inet_sport));

	struct sockets_value socket_value = {0,};
	task = (struct task_struct*) bpf_get_current_task();
	socket_value.mntns = (u64) BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	socket_value.pid_tgid = pid_tgid;
	bpf_get_current_comm(&socket_value.task, sizeof(socket_value.task));
	socket_value.server = 1;

	bpf_map_update_elem(&sockets, &socket_key, &socket_value, BPF_ANY);

cleanup:
	bpf_map_delete_elem(&start, &pid_tgid);
	return 0;
}

static __always_inline int
enter_tcp_connect(struct pt_regs *ctx, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	bpf_map_update_elem(&start, &pid_tgid, &sk, 0);
	return 0;
}

static __always_inline int
exit_tcp_connect(struct pt_regs *ctx, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct task_struct *task;
	struct sock **skpp;
	struct sock *sk;
	struct inet_sock *inet_sock;
	u64 mntns_id;

	skpp = bpf_map_lookup_elem(&start, &pid_tgid);
	if (!skpp)
		return 0;

	if (ret)
		goto cleanup;

	sk = *skpp;
	inet_sock = (struct inet_sock *)sk;

	struct sockets_key socket_key = {0,};

	BPF_CORE_READ_INTO(&socket_key.netns, sk, __sk_common.skc_net.net, ns.inum);

	socket_key.proto = BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol);
	socket_key.port = bpf_ntohs(BPF_CORE_READ(inet_sock, inet_sport));

	struct sockets_value socket_value = {0,};
	task = (struct task_struct*) bpf_get_current_task();
	socket_value.mntns = (u64) BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	socket_value.pid_tgid = pid_tgid;
	bpf_get_current_comm(&socket_value.task, sizeof(socket_value.task));
	socket_value.server = 0;

	bpf_map_update_elem(&sockets, &socket_key, &socket_value, BPF_ANY);

cleanup:
	bpf_map_delete_elem(&start, &pid_tgid);
	return 0;
}

static __always_inline int
probe_release_entry(struct pt_regs *ctx, struct socket *socket)
{
	struct sock *sock;
	struct inet_sock *inet_sock;

	sock = BPF_CORE_READ(socket, sk);
	inet_sock = (struct inet_sock *)sock;

	struct sockets_key socket_key = {0,};

	BPF_CORE_READ_INTO(&socket_key.netns, sock, __sk_common.skc_net.net, ns.inum);

	socket_key.proto = BPF_CORE_READ_BITFIELD_PROBED(sock, sk_protocol);
	socket_key.port = bpf_ntohs(BPF_CORE_READ(inet_sock, inet_sport));

	bpf_map_delete_elem(&sockets, &socket_key);
	return 0;
}

SEC("kprobe/inet_bind")
int BPF_KPROBE(ig_bind_ipv4_e, struct socket *socket)
{
	return probe_bind_entry(ctx, socket);
}

SEC("kretprobe/inet_bind")
int BPF_KRETPROBE(ig_bind_ipv4_x)
{
	return probe_bind_exit(ctx, 4);
}

SEC("kprobe/inet6_bind")
int BPF_KPROBE(ig_bind_ipv6_e, struct socket *socket)
{
	return probe_bind_entry(ctx, socket);
}

SEC("kretprobe/inet6_bind")
int BPF_KRETPROBE(ig_bind_ipv6_x)
{
	return probe_bind_exit(ctx, 6);
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(ig_tcpc_v4_co_e, struct sock *sk)
{
	return enter_tcp_connect(ctx, sk);
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(ig_tcpc_v4_co_x, int ret)
{
	return exit_tcp_connect(ctx, ret);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(ig_tcpc_v6_co_e, struct sock *sk)
{
	return enter_tcp_connect(ctx, sk);
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(ig_tcpc_v6_co_x, int ret)
{
	return exit_tcp_connect(ctx, ret);
}

SEC("kprobe/inet_release")
int BPF_KPROBE(ig_free_ipv4_e, struct socket *socket)
{
	return probe_release_entry(ctx, socket);
}

SEC("kprobe/inet6_release")
int BPF_KPROBE(ig_free_ipv6_e, struct socket *socket)
{
	return probe_release_entry(ctx, socket);
}

char _license[] SEC("license") = "GPL";
