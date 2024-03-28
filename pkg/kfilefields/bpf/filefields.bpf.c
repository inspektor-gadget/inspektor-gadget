// SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// configured by userspace
const volatile u64 socket_ino = 0;

// initialized by this ebpf program
volatile u64 tracer_pid_tgid = 0;

struct file_fields {
	u64 private_data;
	u64 f_op;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int); // index: zero
	__type(value, struct file_fields); // value: file_fields
} ig_file_fields SEC(".maps");

// __scm_send() sends a file descriptor through a unix socket
// using sendmsg() and SCM_RIGHTS. See man cmsg(3) for more details.
//
// This kprobe is used to filter the right call to fget_raw().
//
// __scm_send() exists since the very first git commit in 2005
SEC("kprobe/__scm_send")
int BPF_KPROBE(ig_scm_snd_e, struct socket *sock)
{
	if (socket_ino == 0)
		return 0;
	if ((u64)BPF_CORE_READ(sock, file, f_inode, i_ino) != socket_ino)
		return 0;

	tracer_pid_tgid = bpf_get_current_pid_tgid();

	return 0;
}

// fget_raw() gets a struct file from a file descriptor. It is used by
// __scm_send() to pick up the fd specified by userspace in sendmsg().
//
// fget_raw() exists since Linux v2.6.39 (2011)
SEC("kretprobe/fget_raw")
int BPF_KRETPROBE(ig_fget_x, struct file *ret)
{
	u64 current_pid_tgid;
	struct file_fields *ff;
	int zero = 0;

	if (tracer_pid_tgid == 0)
		return 0;

	// Only check the Inspektor Gadget task selected by __scm_send
	current_pid_tgid = bpf_get_current_pid_tgid();
	if (current_pid_tgid != tracer_pid_tgid)
		return 0;

	ff = bpf_map_lookup_elem(&ig_file_fields, &zero);
	if (!ff)
		return 0;

	ff->private_data = (u64)BPF_CORE_READ(ret, private_data);
	ff->f_op = (u64)BPF_CORE_READ(ret, f_op);

	// Initialize private_data for only one execution of __scm_send
	tracer_pid_tgid = 0;

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
