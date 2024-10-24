/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Hengqi Chen */
/* Copyright (c) 2024 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

enum bind_options_set : __u8 {
	FREEBIND = 0x1,
	TRANSPARENT = 0x2,
	BIND_ADDRESS_NO_PORT = 0x4,
	REUSEADDRESS = 0x8,
	REUSEPORT = 0x10,
};

union bind_options {
	__u8 data;
	struct {
		__u8 freebind : 1;
		__u8 transparent : 1;
		__u8 bind_address_no_port : 1;
		__u8 reuseaddress : 1;
		__u8 reuseport : 1;
	} fields;
};

struct event {
	gadget_timestamp timestamp_raw;
	gadget_mntns_id mntns_id;
	struct gadget_l4endpoint_t addr;

	gadget_comm comm[TASK_COMM_LEN];
	// user-space terminology for pid and tid
	gadget_pid pid;
	gadget_tid tid;
	gadget_uid uid;
	gadget_gid gid;

	gadget_errno error_raw;
	enum bind_options_set opts_raw;
	// TODO: How to get the name of the device?
	__u32 bound_dev_if;
};

const volatile pid_t target_pid = 0;
const volatile bool ignore_errors = true;
const volatile bool filter_by_port = false;

GADGET_PARAM(target_pid);
GADGET_PARAM(ignore_errors);
// TODO: Add support for filtering by port
//GADGET_PARAM(filter_by_port);

/*
 * Highly inspired from:
 * https://github.com/iovisor/bcc/pull/4846/commits/a55b5a0c920f
 */
struct inet_sock___o {
	__u8 freebind : 1;
	__u8 transparent : 1;
	__u8 bind_address_no_port : 1;
};

enum {
	INET_FLAGS_FREEBIND___x = 11,
	INET_FLAGS_TRANSPARENT___x = 15,
	INET_FLAGS_BIND_ADDRESS_NO_PORT___x = 18,
};

struct inet_sock___x {
	unsigned long inet_flags;
};

#define get_inet_sock_flag(inet_sock, flag_name, flag_value)                   \
	({                                                                     \
		__u8 __ret;                                                    \
		if (bpf_core_field_exists(struct inet_sock___o, flag_name)) {  \
			__ret = BPF_CORE_READ_BITFIELD_PROBED(                 \
				(struct inet_sock___o *)inet_sock, flag_name); \
		} else {                                                       \
			unsigned long __flags;                                 \
			__flags = BPF_CORE_READ(                               \
				(struct inet_sock___x *)inet_sock,             \
				inet_flags);                                   \
			__ret = !!((1 << flag_value) & __flags);               \
		}                                                              \
		__ret;                                                         \
	})

static __always_inline __u8 get_inet_sock_freebind(void *inet_sock)
{
	return get_inet_sock_flag(inet_sock, freebind, INET_FLAGS_FREEBIND___x);
}

static __always_inline __u8 get_inet_sock_transparent(void *inet_sock)
{
	return get_inet_sock_flag(inet_sock, transparent,
				  INET_FLAGS_TRANSPARENT___x);
}

static __always_inline __u8 get_inet_sock_bind_address_no_port(void *inet_sock)
{
	return get_inet_sock_flag(inet_sock, bind_address_no_port,
				  INET_FLAGS_BIND_ADDRESS_NO_PORT___x);
}

#define MAX_ENTRIES 10240
#define MAX_PORTS 1024

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(bind, events, event);

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct socket *);
} sockets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PORTS);
	__type(key, __u16);
	__type(value, __u16);
} ports SEC(".maps");

static int probe_entry(struct pt_regs *ctx, struct socket *socket)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	if (target_pid && target_pid != pid)
		return 0;

	bpf_map_update_elem(&sockets, &tid, &socket, BPF_ANY);
	return 0;
};

static int probe_exit(struct pt_regs *ctx, short ver)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	__u64 uid_gid = bpf_get_current_uid_gid();
	u64 mntns_id;
	struct socket **socketp, *socket;
	struct inet_sock *inet_sock;
	struct sock *sock;
	union bind_options opts;
	struct event *event;
	__u16 sport = 0, *port;
	int ret;

	socketp = bpf_map_lookup_elem(&sockets, &tid);
	if (!socketp)
		return 0;

	mntns_id = gadget_get_mntns_id();
	if (gadget_should_discard_mntns_id(mntns_id))
		goto cleanup;

	ret = PT_REGS_RC(ctx);
	if (ignore_errors && ret != 0)
		goto cleanup;

	socket = *socketp;
	sock = BPF_CORE_READ(socket, sk);
	inet_sock = (struct inet_sock *)sock;

	sport = bpf_ntohs(BPF_CORE_READ(inet_sock, inet_sport));
	port = bpf_map_lookup_elem(&ports, &sport);
	if (filter_by_port && !port)
		goto cleanup;

	opts.fields.freebind = get_inet_sock_freebind(inet_sock);
	opts.fields.transparent = get_inet_sock_transparent(inet_sock);
	opts.fields.bind_address_no_port =
		get_inet_sock_bind_address_no_port(inet_sock);
	opts.fields.reuseaddress =
		BPF_CORE_READ_BITFIELD_PROBED(sock, __sk_common.skc_reuse);
	opts.fields.reuseport =
		BPF_CORE_READ_BITFIELD_PROBED(sock, __sk_common.skc_reuseport);

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		goto cleanup;

	event->opts_raw = opts.data;
	event->pid = pid;
	event->tid = tid;
	event->bound_dev_if = BPF_CORE_READ(sock, __sk_common.skc_bound_dev_if);
	event->error_raw = -ret;
	event->mntns_id = mntns_id;
	event->timestamp_raw = bpf_ktime_get_boot_ns();
	event->uid = (u32)uid_gid;
	event->gid = (u32)(uid_gid >> 32);
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	event->addr.port = sport;
	event->addr.version = ver;
	event->addr.proto_raw =
		BPF_CORE_READ_BITFIELD_PROBED(sock, sk_protocol);

	if (ver == 4) {
		bpf_probe_read_kernel(&event->addr.addr_raw.v4,
				      sizeof(event->addr.addr_raw.v4),
				      &inet_sock->inet_saddr);
	} else { /* ver == 6 */
		bpf_probe_read_kernel(
			&event->addr.addr_raw.v6,
			sizeof(event->addr.addr_raw.v6),
			sock->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	}

	/* emit event */
	gadget_submit_buf(ctx, &events, event, sizeof(*event));

cleanup:
	bpf_map_delete_elem(&sockets, &tid);
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

char LICENSE[] SEC("license") = "Dual BSD/GPL";
