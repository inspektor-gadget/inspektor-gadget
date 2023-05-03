// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note

/* Copyright (c) 2023 The Inspektor Gadget authors */

/*
 * Inspired by the BPF selftests in the Linux tree:
 * https://github.com/torvalds/linux/blob/v5.13/tools/testing/selftests/bpf/progs/bpf_iter_tcp4.c
 * https://github.com/torvalds/linux/blob/v5.13/tools/testing/selftests/bpf/progs/bpf_iter_udp4.c
 */

/*
 * This BPF program uses the GPL-restricted function bpf_seq_printf().
 */

#include <vmlinux/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "mntns_filter.h"

char _license[] SEC("license") = "GPL";

static const char tcp_proto[] = "TCP";
static const char udp_proto[] = "UDP";

const volatile __u64 socket_file_ops_addr = 0;

const volatile bool skip_tcp = false;
const volatile bool skip_udp = false;

#ifndef AF_INET
#define AF_INET		2	/* Internet IP Protocol 	*/
#endif

#ifndef AF_INET6
#define AF_INET6 10      /* IP version 6                 */
#endif

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
	const struct socket *sk_socket = BPF_CORE_READ(sk, sk_socket);
	const struct inode *inode;
	unsigned long ino;

	if (!sk_socket)
		return 0;

	inode = &container_of(sk_socket, struct socket_alloc, socket)->vfs_inode;
	bpf_probe_read_kernel(&ino, sizeof(ino), &inode->i_ino);
	return ino;
}

static int dump_sock(struct seq_file *seq,
                         struct task_struct *task,
                         struct sock *sock,
                         const char *protocol,
                         int ipversion)
{
	const struct inet_sock *inet = (struct inet_sock *)sock;

	__be32 src = BPF_CORE_READ(inet, sk.__sk_common.skc_rcv_saddr);
	__u16 srcp = BPF_CORE_READ(inet, inet_sport);
	__be32 dest = BPF_CORE_READ(inet, sk.__sk_common.skc_daddr);
	__u16 destp = BPF_CORE_READ(inet, sk.__sk_common.skc_dport);
	unsigned char state = BPF_CORE_READ(sock, __sk_common.skc_state);
	long ino = sock_i_ino(sock);
	__u32 netns = BPF_CORE_READ(sock, __sk_common.skc_net.net, ns.inum);

	u64 mntns_id = (u64) BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	struct task_struct *parent = task->real_parent;
	pid_t parent_pid;
	if (!parent)
		parent_pid = -1;
	else
		parent_pid = parent->pid;

	/*
	 * Notice that client side program is expecting socket information exactly
	 * in this format:
	 *
	 * protocol: "TCP" or "UDP"
	 * family: 4 or 6
	 * IP addresses: Dot-decimal notation.
	 * IP ports: Hexadecimal in host-byte order.
	 * state: Hexadecimal of https://github.com/torvalds/linux/blob/v5.13/include/net/tcp_states.h#L12-L24
	 * ino: unsigned long.
	 * netns: unsigned int.
	 * mntns_id: unsigned long long.
	 * parent_pid: int.
	 * pid: int.
	 * uid: unsigned int.
	 * gid: unsigned int.
	 * comm: string.
	 */
	BPF_SEQ_PRINTF(seq, "%s %d ",
		protocol, ipversion);
	if (ipversion == 4) {
		BPF_SEQ_PRINTF(seq, "%pI4 %pI4 ", &src, &dest);
	} else {
		BPF_SEQ_PRINTF(seq, "%pI6 %pI6 ",
		&sock->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8[0],
		&sock->__sk_common.skc_v6_daddr.in6_u.u6_addr8[0]);
	}

	BPF_SEQ_PRINTF(seq, "%04X %04X ",
		bpf_ntohs(srcp), bpf_ntohs(destp));
	BPF_SEQ_PRINTF(seq, "%02X %lu %u %llu ",
		state, ino, netns, mntns_id);
	BPF_SEQ_PRINTF(seq, "%d %d %u %u %s\n",
		parent_pid, task->tgid,
		task->cred->uid.val,
		task->cred->gid.val,
		task->comm);
	return 0;
}

// This iterates on all the sockets (from all tasks) and updates the sockets
// map. This is useful to get the initial sockets that were already opened
// before the socket enricher was attached.
SEC("iter/task_file")
int ig_sockets_it(struct bpf_iter__task_file *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct file *file = ctx->file;
	struct task_struct *task = ctx->task;
	u64 mntns_id;

	if (!file || !task)
		return 0;

	mntns_id = (u64) BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	// Check that the file descriptor is a socket.
	// TODO: cilium/ebpf doesn't support .ksyms, so we get the address of
	// socket_file_ops from userspace.
	// See: https://github.com/cilium/ebpf/issues/761
	if (socket_file_ops_addr == 0 || (__u64)(file->f_op) != socket_file_ops_addr)
		return 0;

	// file->private_data is a struct socket because we checked f_op.
	struct socket *socket = BPF_CORE_READ(file, private_data);
	struct sock *sock = BPF_CORE_READ(socket, sk);
	if (!sock) {
		return 0;
	}

	__u16 family = BPF_CORE_READ(sock, __sk_common.skc_family);
	int ipversion;
	switch (family) {
	case AF_INET:
		ipversion = 4;
		break;
	case AF_INET6:
		ipversion = 6;
		break;
	default:
		return 0;
	}

	__u16 proto = BPF_CORE_READ_BITFIELD_PROBED(sock, sk_protocol);
	switch (proto) {
	case IPPROTO_TCP:
		if (skip_tcp)
			return 0;

		return dump_sock(seq, task, sock, tcp_proto, ipversion);

	case IPPROTO_UDP:
		if (skip_udp)
			return 0;

		return dump_sock(seq, task, sock, udp_proto, ipversion);
	}


	return 0;
}
