// SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0
/* Copyright (c) 2023 The Inspektor Gadget authors */

#include <vmlinux/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include <bpf/bpf_helpers.h>

#include "sockets-map.h"

#define MAX_ENTRIES	10240

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

const volatile __u64 socket_file_ops_addr = 0;

static __always_inline void
prepare_socket_key(struct sockets_key *socket_key, struct sock *sock)
{
	struct inet_sock *inet_sock = (struct inet_sock *)sock;
	BPF_CORE_READ_INTO(&socket_key->netns, sock, __sk_common.skc_net.net, ns.inum);
	BPF_CORE_READ_INTO(&socket_key->family, sock, __sk_common.skc_family);
	socket_key->proto = BPF_CORE_READ_BITFIELD_PROBED(sock, sk_protocol);
	socket_key->port = bpf_ntohs(BPF_CORE_READ(inet_sock, inet_sport));
}

static __always_inline void
insert_current_socket(struct sock *sock)
{
	struct sockets_key socket_key = {0,};
	prepare_socket_key(&socket_key, sock);

	struct sockets_value socket_value = {0,};
	// use 'current' task
	struct task_struct *task = (struct task_struct*) bpf_get_current_task();
	socket_value.mntns = (u64) BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	socket_value.pid_tgid = bpf_get_current_pid_tgid();
	socket_value.uid_gid = bpf_get_current_uid_gid();
	bpf_get_current_comm(&socket_value.task, sizeof(socket_value.task));
	socket_value.sock = (__u64) sock;

	bpf_map_update_elem(&sockets, &socket_key, &socket_value, BPF_ANY);
}

static __always_inline void
insert_socket_from_iter(struct sock *sock, struct task_struct *task)
{
	struct sockets_key socket_key = {0,};
	prepare_socket_key(&socket_key, sock);

	struct sockets_value socket_value = {0,};
	// use given task
	socket_value.pid_tgid = ((u64)task->tgid) << 32 | task->pid;
	// The VFS code might temporary substitute task->cred by other creds during overlayfs
	// copyup. In this case, we want the real creds of the process, not the creds temporarily
	// substituted by VFS overlayfs copyup.
	// https://kernel.org/doc/html/v6.2-rc8/security/credentials.html#overriding-the-vfs-s-use-of-credentials
	socket_value.uid_gid = ((u64)task->real_cred->gid.val) << 32 | task->real_cred->uid.val;
	__builtin_memcpy(&socket_value.task, task->comm, sizeof(socket_value.task));
	socket_value.mntns = (u64) task->nsproxy->mnt_ns->ns.inum;
	socket_value.sock = (__u64) sock;

	// If the endpoint was not present, add it and we're done.
	struct sockets_value *old_socket_value =
		(struct sockets_value *) bpf_map_lookup_elem(&sockets, &socket_key);
	if (!old_socket_value) {
		// Use BPF_NOEXIST: if an entry was inserted just after the check, this
		// is because the bpf iterator for initial sockets runs in
		// parallel to other kprobes and we prefer the information from the
		// other kprobes because their data is more accurate (e.g. correct
		// thread).
		bpf_map_update_elem(&sockets, &socket_key, &socket_value, BPF_NOEXIST);
		return;
	}

	// At this point, the endpoint was already present, we need to determine
	// the best entry between the existing one and the new one.

	// When iterating on initial sockets, we get both passive and active
	// sockets (server side). We want the passive socket because we don't
	// want the endpoint to be removed from the map when just one
	// connection is terminated. We cannot determine if an active socket
	// is server side or client side, so we add active socket anyway on the
	// chance that it is client side. It will be fine for server side too,
	// because the passive socket will be added later, overwriting the
	// active socket.
	u64 flags = BPF_NOEXIST;
	if (BPF_CORE_READ(sock, __sk_common.skc_state) == TCP_LISTEN)
		flags = BPF_ANY;

	bpf_map_update_elem(&sockets, &socket_key, &socket_value, flags);
}

static __always_inline int
remove_socket(struct sock *sock)
{
	struct inet_sock *inet_sock = (struct inet_sock *)sock;
	struct sockets_key socket_key = {0,};

	BPF_CORE_READ_INTO(&socket_key.family, sock, __sk_common.skc_family);
	BPF_CORE_READ_INTO(&socket_key.netns, sock, __sk_common.skc_net.net, ns.inum);

	socket_key.proto = BPF_CORE_READ_BITFIELD_PROBED(sock, sk_protocol);
	socket_key.port = bpf_ntohs(BPF_CORE_READ(inet_sock, inet_sport));

	struct sockets_value *socket_value = bpf_map_lookup_elem(&sockets, &socket_key);
	if (socket_value == NULL)
		return 0;

	if (socket_value->sock != (__u64) sock)
		return 0;

	if (socket_value->deletion_timestamp == 0) {
		// bpf timers are only available in Linux 5.15.
		// Use bpf iterators (Linux 5.8) controlled from userspace instead.
		// Avoid bpf_ktime_get_boot_ns() to support older kernels
		socket_value->deletion_timestamp = bpf_ktime_get_ns();
	}
	return 0;
}

// This iterates on all the sockets (from all tasks) and updates the sockets
// map. This is useful to get the initial sockets that were already opened
// before the socket enricher was attached.
SEC("iter/task_file")
int ig_sockets_it(struct bpf_iter__task_file *ctx)
{
	struct file *file = ctx->file;
	struct task_struct *task = ctx->task;

	if (!file || !task)
		return 0;

	// Check that the file descriptor is a socket.
	// TODO: cilium/ebpf doesn't support .ksyms, so we get the address of
	// socket_file_ops from userspace.
	// See: https://github.com/cilium/ebpf/issues/761
	if (socket_file_ops_addr == 0 || (__u64)(file->f_op) != socket_file_ops_addr)
		return 0;

	// file->private_data is a struct socket because we checked f_op.
	struct socket *socket = (struct socket *) file->private_data;
	struct sock *sock = BPF_CORE_READ(socket, sk);
	__u16 family = BPF_CORE_READ(sock, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;

	// Since the iterator is not executed from the context of the process that
	// opened the socket, we need to pass the task_struct to the map.
	insert_socket_from_iter(sock, task);
	return 0;
}

// This iterator is called from a Go Ticker to remove expired sockets
SEC("iter/bpf_map_elem")
int ig_sk_cleanup(struct bpf_iter__bpf_map_elem *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	__u32 seq_num = ctx->meta->seq_num;
	struct bpf_map *map = ctx->map;
	struct sockets_key *socket_key = ctx->key;
	struct sockets_key tmp_key;
	struct sockets_value *socket_value = ctx->value;

	if (!socket_key || !socket_value)
		return 0;

	__u64 now = bpf_ktime_get_ns();
	__u64 deletion_timestamp = socket_value->deletion_timestamp;
	__u64 socket_expiration_ns = 1000ULL*1000ULL*1000ULL*5ULL; // 5 seconds

	if (deletion_timestamp != 0 && deletion_timestamp + socket_expiration_ns < now) {
		// The socket is expired, remove it from the map.
		__builtin_memcpy(&tmp_key, socket_key, sizeof(struct sockets_key));
		bpf_map_delete_elem(&sockets, &tmp_key);
		return 0;
	}

	return 0;
}

// probe_bind_entry & probe_bind_exit are used:
// - server side
// - for both UDP and TCP
// - for both IPv4 and IPv6
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
static __always_inline int
enter_tcp_connect(struct pt_regs *ctx, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&start, &pid_tgid, &sk, 0);

	// Add socket to the map before the connection is established, so that
	// early SYN packets can be enriched.
	insert_current_socket(sk);

	return 0;
}

static __always_inline int
exit_tcp_connect(struct pt_regs *ctx, int ret)
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
static __always_inline int
enter_udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len)
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
