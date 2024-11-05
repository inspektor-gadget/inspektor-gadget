/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024 The Inspektor Gadget authors */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <gadget/common.h>
#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/filesystem.h>
#include <gadget/types.h>

#define PATH_MAX 4096

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;

	u64 socket_ino;
	u32 sockfd;
	u32 fd;
	char file[PATH_MAX];
};

// Context between tracepoints enter/exit sendmsg
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240); // sendmsg can sleep
	__type(key, u64); // pid_tgid
	__type(value, u32); // sockfd
} sendmsg_ctx SEC(".maps");

// Context between kprobe/kretprobe __scm_send
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, u64); // pid_tgid
	__type(value, u64); // socket_ino
} scm_send_ctx SEC(".maps");

// Context between kprobe/kretprobe fget_raw
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, u64); // pid_tgid
	__type(value, unsigned int); // fd
} fget_raw_ctx SEC(".maps");

const volatile pid_t target_pid = 0;
GADGET_PARAM(target_pid);

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(fdpass, events, event);

static __always_inline int sys_sendmsg_e(struct syscall_trace_enter *ctx)
{
	u64 pid_tgid;
	u32 sockfd;

	if (gadget_should_discard_mntns_id(gadget_get_mntns_id()))
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;

	if (target_pid && target_pid != pid)
		return 0;

	sockfd = (u32)ctx->args[0];
	bpf_map_update_elem(&sendmsg_ctx, &pid_tgid, &sockfd, BPF_ANY);
	return 0;
}

static __always_inline int sys_sendmsg_x(struct syscall_trace_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&sendmsg_ctx, &pid_tgid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int sendmsg_e(struct syscall_trace_enter *ctx)
{
	return sys_sendmsg_e(ctx);
}

SEC("tracepoint/syscalls/sys_exit_sendmsg")
int sendmsg_x(struct syscall_trace_exit *ctx)
{
	return sys_sendmsg_x(ctx);
}

SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int sendmmsg_e(struct syscall_trace_enter *ctx)
{
	return sys_sendmsg_e(ctx);
}

SEC("tracepoint/syscalls/sys_exit_sendmmsg")
int sendmmsg_x(struct syscall_trace_exit *ctx)
{
	return sys_sendmsg_x(ctx);
}

// __scm_send() sends a file descriptor through a unix socket
// using sendmsg() and SCM_RIGHTS. See man cmsg(3) for more details.
//
// This kprobe is used to filter the right call to fget_raw().
//
// __scm_send() exists since the very first git commit in 2005
SEC("kprobe/__scm_send")
int BPF_KPROBE(scm_snd_e, struct socket *sock)
{
	u64 pid_tgid;
	u64 socket_ino;

	if (gadget_should_discard_mntns_id(gadget_get_mntns_id()))
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	socket_ino = (u64)BPF_CORE_READ(sock, file, f_inode, i_ino);

	bpf_map_update_elem(&scm_send_ctx, &pid_tgid, &socket_ino, BPF_ANY);
	return 0;
}

SEC("kretprobe/__scm_send")
int BPF_KRETPROBE(scm_snd_x)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&scm_send_ctx, &pid_tgid);
	return 0;
}

// fget_raw() gets a struct file from a file descriptor. It is used by
// __scm_send() to pick up the fd specified by userspace in sendmsg().
//
// fget_raw() exists since Linux v2.6.39 (2011)
SEC("kprobe/fget_raw")
int BPF_KPROBE(fget_raw_e, unsigned int _fd)
{
	u64 pid_tgid;
	u64 *socket_ino;
	u32 fd;

	if (gadget_should_discard_mntns_id(gadget_get_mntns_id()))
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	fd = (u32)_fd;

	socket_ino = bpf_map_lookup_elem(&scm_send_ctx, &pid_tgid);
	if (!socket_ino)
		return 0;

	bpf_map_update_elem(&fget_raw_ctx, &pid_tgid, &fd, BPF_ANY);
	return 0;
}

SEC("kretprobe/fget_raw")
int BPF_KRETPROBE(fget_raw_x, struct file *ret)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u64 *socket_ino;
	u32 *fd;
	u32 *sockfd;
	struct event *eventp;
	struct path f_path;
	char *c_path;

	socket_ino = bpf_map_lookup_elem(&scm_send_ctx, &pid_tgid);
	if (!socket_ino)
		return 0;

	fd = bpf_map_lookup_elem(&fget_raw_ctx, &pid_tgid);
	if (!fd)
		return 0;

	sockfd = bpf_map_lookup_elem(&sendmsg_ctx, &pid_tgid);
	if (!sockfd)
		goto end;

	eventp = gadget_reserve_buf(&events, sizeof(*eventp));
	if (!eventp)
		goto end;

	eventp->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&eventp->proc);

	eventp->socket_ino = *socket_ino;
	eventp->sockfd = *sockfd;
	eventp->fd = *fd;

	f_path = BPF_CORE_READ(ret, f_path);
	c_path = get_path_str(&f_path);
	bpf_probe_read_kernel_str(eventp->file, sizeof(eventp->file), c_path);

	gadget_submit_buf(ctx, &events, eventp, sizeof(*eventp));

end:
	bpf_map_delete_elem(&fget_raw_ctx, &pid_tgid);

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
