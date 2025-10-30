// SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0
/* Copyright (c) 2023 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include <bpf/bpf_helpers.h>

#include <gadget/filesystem.h>
#include <gadget/sockets-map.h>
#include "socket-enricher-helpers.h"

#define AF_INET 2 /* Internet IP Protocol */
#define AF_INET6 10 /* IP version 6 */

#define MAX_ENTRIES 10240

// The map 'start' keeps context between a kprobe and a kretprobe
// Keys: pid_tgid
// Values: the argument of the kprobe function:
// - When used in bind: struct socket *
// - When used in tcp_connect: struct sock *
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, void *);
} start SEC(".maps");

const volatile bool disable_bpf_iterators = 0;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct gadget_socket_value);
} ig_tmp_sockets_value SEC(".maps");

static const struct gadget_socket_value empty_sockets_value = {};

static __always_inline void insert_current_socket(struct sock *sock)
{
	int zero = 0;
	struct gadget_socket_key socket_key = {
		0,
	};
	prepare_socket_key(&socket_key, sock);

	// insert_current_socket is called for each udp packed emitted. To improve
	// performance, don't add a socket if it is already in the map.
	struct gadget_socket_value *already_exists =
		bpf_map_lookup_elem(&gadget_sockets, &socket_key);
	if (already_exists && already_exists->deletion_timestamp == 0)
		return;

	if (bpf_map_update_elem(&ig_tmp_sockets_value, &zero,
				&empty_sockets_value, BPF_ANY))
		return;

	struct gadget_socket_value *socket_value =
		bpf_map_lookup_elem(&ig_tmp_sockets_value, &zero);
	if (!socket_value)
		return;

	// use 'current' task
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	struct fs_struct *fs = BPF_CORE_READ(task, fs);
	struct file *exe_file = BPF_CORE_READ(task, mm, exe_file);
	socket_value->mntns =
		(u64)BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	socket_value->pid_tgid = bpf_get_current_pid_tgid();
	socket_value->uid_gid = bpf_get_current_uid_gid();
	bpf_get_current_comm(&socket_value->task, sizeof(socket_value->task));
	if (parent != NULL) {
		bpf_probe_read_kernel(&socket_value->ptask,
				      sizeof(socket_value->ptask),
				      parent->comm);
		socket_value->ppid = (__u32)BPF_CORE_READ(parent, tgid);
		socket_value->ptid = (__u32)BPF_CORE_READ(parent, pid);
	}

	socket_value->sock = (__u64)sock;
	if (socket_key.family == AF_INET6)
		socket_value->ipv6only = BPF_CORE_READ_BITFIELD_PROBED(
			sock, __sk_common.skc_ipv6only);

	if (bpf_core_field_exists(socket_value->cwd)) {
		int cwd_size = bpf_core_field_size(socket_value->cwd);
		char *cwd = get_path_str(&fs->pwd);
		bpf_probe_read_kernel_str(socket_value->cwd, cwd_size, cwd);
	}
	if (bpf_core_field_exists(socket_value->exepath)) {
		int exepath_size = bpf_core_field_size(socket_value->exepath);
		char *exepath = get_path_str(&exe_file->f_path);
		bpf_probe_read_kernel_str(socket_value->exepath, exepath_size,
					  exepath);
	}

	bpf_map_update_elem(&gadget_sockets, &socket_key, socket_value,
			    BPF_ANY);
}

static __always_inline int remove_socket(struct sock *sock)
{
	struct inet_sock *inet_sock = (struct inet_sock *)sock;
	struct gadget_socket_key socket_key = {
		0,
	};

	BPF_CORE_READ_INTO(&socket_key.family, sock, __sk_common.skc_family);
	BPF_CORE_READ_INTO(&socket_key.netns, sock, __sk_common.skc_net.net,
			   ns.inum);

	socket_key.proto = BPF_CORE_READ_BITFIELD_PROBED(sock, sk_protocol);
	socket_key.port = bpf_ntohs(BPF_CORE_READ(inet_sock, inet_sport));

	struct gadget_socket_value *socket_value =
		bpf_map_lookup_elem(&gadget_sockets, &socket_key);
	if (socket_value == NULL)
		return 0;

	if (socket_value->sock != (__u64)sock)
		return 0;

	if (socket_value->deletion_timestamp == 0) {
		// bpf timers are not used because they require Linux 5.15 and we want
		// to support older kernels.
		// Use bpf iterators if available (Linux 5.8) otherwise delete
		// directly.
		if (disable_bpf_iterators) {
			bpf_map_delete_elem(&gadget_sockets, &socket_key);
		} else {
			// Avoid bpf_ktime_get_boot_ns() to support older kernels
			socket_value->deletion_timestamp = bpf_ktime_get_ns();
		}
	}
	return 0;
}

// probe_bind_entry & probe_bind_exit are used:
// - server side
// - for both UDP and TCP
// - for both IPv4 and IPv6
static __always_inline int probe_bind_entry(struct pt_regs *ctx,
					    struct socket *socket)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	bpf_map_update_elem(&start, &pid_tgid, &socket, BPF_ANY);
	return 0;
};

static __always_inline int probe_bind_exit(struct pt_regs *ctx, short ver)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct socket **socketp, *socket;
	struct sock *sock;
	int ret;

	socketp = bpf_map_lookup_elem(&start, &pid_tgid);
	if (!socketp)
		return 0;

	ret = PT_REGS_RC(ctx);
	if (ret != 0)
		goto cleanup;

	socket = *socketp;
	sock = BPF_CORE_READ(socket, sk);

	insert_current_socket(sock);

cleanup:
	bpf_map_delete_elem(&start, &pid_tgid);
	return 0;
}

// enter_tcp_connect & exit_tcp_connect are used:
// - client side
// - for TCP only
// - for both IPv4 and IPv6
static __always_inline int enter_tcp_connect(struct pt_regs *ctx,
					     struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&start, &pid_tgid, &sk, 0);

	// Add socket to the map before the connection is established, so that
	// early SYN packets can be enriched.
	insert_current_socket(sk);

	return 0;
}

static __always_inline int exit_tcp_connect(struct pt_regs *ctx, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct task_struct *task;
	struct sock **skpp;
	struct sock *sk;

	skpp = bpf_map_lookup_elem(&start, &pid_tgid);
	if (!skpp)
		return 0;

	sk = *skpp;

	if (ret)
		remove_socket(sk);

	bpf_map_delete_elem(&start, &pid_tgid);
	return 0;
}

// enter_udp_sendmsg is used:
// - client side
// - for UDP only
// - for both IPv4 and IPv6
static __always_inline int enter_udp_sendmsg(struct pt_regs *ctx,
					     struct sock *sk,
					     struct msghdr *msg, size_t len)
{
	insert_current_socket(sk);
	return 0;
}

// probe_release_entry is used:
// - for both server and client sides
// - for both UDP and TCP
// - for both IPv4 and IPv6
static __always_inline int
probe_release_entry(struct pt_regs *ctx, struct socket *socket, __u16 family)
{
	struct sock *sock;

	sock = BPF_CORE_READ(socket, sk);

	// The kernel function inet6_release() calls inet_release() and we have a kprobe on both, so beware if it is called
	// in the right context.
	if (BPF_CORE_READ(sock, __sk_common.skc_family) != family)
		return 0;

	return remove_socket(sock);
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

SEC("kprobe/tcp_connect")
int BPF_KPROBE(ig_tcp_co_e, struct sock *sk)
{
	return enter_tcp_connect(ctx, sk);
}

SEC("kretprobe/tcp_connect")
int BPF_KRETPROBE(ig_tcp_co_x, int ret)
{
	return exit_tcp_connect(ctx, ret);
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(ig_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
	return enter_udp_sendmsg(ctx, sk, msg, len);
}

SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(ig_udp6_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
	return enter_udp_sendmsg(ctx, sk, msg, len);
}

SEC("kprobe/inet_release")
int BPF_KPROBE(ig_free_ipv4_e, struct socket *socket)
{
	return probe_release_entry(ctx, socket, AF_INET);
}

SEC("kprobe/inet6_release")
int BPF_KPROBE(ig_free_ipv6_e, struct socket *socket)
{
	return probe_release_entry(ctx, socket, AF_INET6);
}

char _license[] SEC("license") = "GPL";
