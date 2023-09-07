// SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0
/* Copyright (c) 2023 The Inspektor Gadget authors */

#include <vmlinux/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include <bpf/bpf_helpers.h>

#include "sockets-map.h"
#include "socket-enricher-helpers.h"

const volatile __u64 socket_file_ops_addr = 0;

static __always_inline void insert_socket_from_iter(struct sock *sock,
						    struct task_struct *task)
{
	struct sockets_key socket_key = {
		0,
	};
	prepare_socket_key(&socket_key, sock);

	struct sockets_value socket_value = {
		0,
	};
	// use given task
	socket_value.pid_tgid = ((u64)task->tgid) << 32 | task->pid;
	// The VFS code might temporary substitute task->cred by other creds during overlayfs
	// copyup. In this case, we want the real creds of the process, not the creds temporarily
	// substituted by VFS overlayfs copyup.
	// https://kernel.org/doc/html/v6.2-rc8/security/credentials.html#overriding-the-vfs-s-use-of-credentials
	socket_value.uid_gid = ((u64)task->real_cred->gid.val) << 32 |
			       task->real_cred->uid.val;
	__builtin_memcpy(&socket_value.task, task->comm,
			 sizeof(socket_value.task));
	socket_value.mntns = (u64)task->nsproxy->mnt_ns->ns.inum;
	socket_value.sock = (__u64)sock;
	socket_value.ipv6only =
		BPF_CORE_READ_BITFIELD_PROBED(sock, __sk_common.skc_ipv6only);

	// If the endpoint was not present, add it and we're done.
	struct sockets_value *old_socket_value =
		(struct sockets_value *)bpf_map_lookup_elem(&gadget_sockets,
							    &socket_key);
	if (!old_socket_value) {
		// Use BPF_NOEXIST: if an entry was inserted just after the check, this
		// is because the bpf iterator for initial sockets runs in
		// parallel to other kprobes and we prefer the information from the
		// other kprobes because their data is more accurate (e.g. correct
		// thread).
		bpf_map_update_elem(&gadget_sockets, &socket_key, &socket_value,
				    BPF_NOEXIST);
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
	if (BPF_CORE_READ(sock, __sk_common.skc_state) == TCP_LISTEN)
		bpf_map_update_elem(&gadget_sockets, &socket_key, &socket_value,
				    BPF_ANY);
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
	if (socket_file_ops_addr == 0 ||
	    (__u64)(file->f_op) != socket_file_ops_addr)
		return 0;

	// file->private_data is a struct socket because we checked f_op.
	struct socket *socket = (struct socket *)file->private_data;
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
	__u64 socket_expiration_ns =
		1000ULL * 1000ULL * 1000ULL * 5ULL; // 5 seconds

	if (deletion_timestamp != 0 &&
	    deletion_timestamp + socket_expiration_ns < now) {
		// The socket is expired, remove it from the map.
		__builtin_memcpy(&tmp_key, socket_key,
				 sizeof(struct sockets_key));
		bpf_map_delete_elem(&gadget_sockets, &tmp_key);
		return 0;
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
