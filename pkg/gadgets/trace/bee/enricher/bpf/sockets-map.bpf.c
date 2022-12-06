// SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0
/* Copyright (c) 2021 The Inspektor Gadget authors */

#include <vmlinux/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include <bpf/bpf_helpers.h>

#include "sockets-map.h"

#define MAX_ENTRIES	10240

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct socket *);
} start SEC(".maps");

static int probe_entry(struct pt_regs *ctx, struct socket *socket)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	bpf_map_update_elem(&start, &pid_tgid, &socket, BPF_ANY);
	return 0;
};

static int probe_exit(struct pt_regs *ctx, short ver)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	struct task_struct *task;
	struct socket **socketp, *socket;
	struct inet_sock *inet_sock;
	struct sock *sock;
	__u16 sport = 0;
	int ret;

	bpf_printk("probe_exit");

	socketp = bpf_map_lookup_elem(&start, &pid_tgid);
	if (!socketp)
		return 0;

	bpf_printk("probe_exit: pid_tgid found");

	ret = PT_REGS_RC(ctx);
	if (ret != 0)
		goto cleanup;

	bpf_printk("probe_exit: pid_tgid not fail");

	bpf_printk("probe_exit: pid_tgid ver");

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
	socket_value.pid = pid;
	bpf_get_current_comm(&socket_value.task, sizeof(socket_value.task));

	bpf_map_update_elem(&sockets, &socket_key, &socket_value, BPF_ANY);

cleanup:
	bpf_map_delete_elem(&start, &pid_tgid);
	return 0;
}

SEC("kprobe/inet_bind")
int BPF_KPROBE(ig_bind_ipv4_e, struct socket *socket)
{
	return probe_entry(ctx, socket);
}

SEC("kretprobe/inet_bind")
int BPF_KRETPROBE(ig_bind_ipv4_x)
{
	return probe_exit(ctx, 4);
}

SEC("kprobe/inet6_bind")
int BPF_KPROBE(ig_bind_ipv6_e, struct socket *socket)
{
	return probe_entry(ctx, socket);
}

SEC("kretprobe/inet6_bind")
int BPF_KRETPROBE(ig_bind_ipv6_x)
{
	return probe_exit(ctx, 6);
}

char _license[] SEC("license") = "GPL";
