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
	__type(value, struct sockets_value);
} ig_tmp_sockets_value SEC(".maps");

static const struct sockets_value empty_sockets_value = {};

static __always_inline void insert_current_socket(struct sock *sock)
{
	int zero = 0;
	__u64 socket_key = bpf_get_socket_cookie(sock);

	// insert_current_socket is called for each udp packed emitted. To improve
	// performance, don't add a socket if it is already in the map.
	struct sockets_value *already_exists =
		bpf_map_lookup_elem(&gadget_sockets, &socket_key);
	if (already_exists && already_exists->deletion_timestamp == 0)
		return;

	if (bpf_map_update_elem(&ig_tmp_sockets_value, &zero,
				&empty_sockets_value, BPF_ANY))
		return;

	struct sockets_value *socket_value =
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
	}
//	char *cwd = get_path_str(&fs->pwd);
//	bpf_probe_read_kernel_str(socket_value->cwd, sizeof(socket_value->cwd),
//				  cwd);
//	char *exepath = get_path_str(&exe_file->f_path);
//	bpf_probe_read_kernel_str(socket_value->exepath,
//				  sizeof(socket_value->exepath), exepath);

	socket_value->sock = (__u64)sock;
	//if (socket_key.family == AF_INET6)
	//	socket_value->ipv6only = BPF_CORE_READ_BITFIELD_PROBED(
	//		sock, __sk_common.skc_ipv6only);

	bpf_map_update_elem(&gadget_sockets, &socket_key, socket_value,
				BPF_ANY);
}


static __always_inline int remove_socket(struct sock *sock)
{
	struct inet_sock *inet_sock = (struct inet_sock *)sock;
	__u64 socket_key = bpf_get_socket_cookie(sock);
	bpf_map_delete_elem(&gadget_sockets, &socket_key);

	return 0;
}

// Updated sock_create function to get parent info
SEC("cgroup/sock_create")
int cgroup_sock_create(struct bpf_sock *sk) {
	insert_current_socket((void*)sk);
	return 1;
}

SEC("cgroup/sock_release")
int cgroup_sock_release(struct bpf_sock *sk) {
	// Remove the socket from the map when it is released
	remove_socket((void*)sk);
	return 1;
}

char _license[] SEC("license") = "GPL";
