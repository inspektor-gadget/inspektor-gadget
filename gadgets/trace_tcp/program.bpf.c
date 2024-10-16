// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Microsoft Corporation
//
// Based on tcptracer(8) from BCC by Kinvolk GmbH and
// tcpconnect(8) by Anton Protopopov
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>
#include <gadget/macros.h>
#include <gadget/buffer.h>

/* The maximum number of items in maps */
#define MAX_ENTRIES 8192

#define TASK_COMM_LEN 16

enum event_type : u8 {
	connect,
	accept,
	close,
};

struct event {
	gadget_timestamp timestamp_raw;
	gadget_mntns_id mntns_id;
	gadget_netns_id netns_id;

	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;

	char comm[TASK_COMM_LEN];
	// user-space terminology for pid and tid
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 gid;

	enum event_type type_raw;
};

const volatile uid_t filter_uid = -1;
const volatile pid_t filter_pid = 0;

GADGET_PARAM(filter_uid);
GADGET_PARAM(filter_pid);

/* Define here, because there are conflicts with include files */
#define AF_INET 2
#define AF_INET6 10

// we need this to make sure the compiler doesn't remove our struct
const enum event_type unused_eventtype __attribute__((unused));

/*
 * tcp_set_state doesn't run in the context of the process that initiated the
 * connection so we need to store a map TUPLE -> PID to send the right PID on
 * the event.
 */
struct tuple_key_t {
	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;
	u32 netns;
};

struct pid_comm_t {
	u64 pid_tgid;
	char comm[TASK_COMM_LEN];
	u64 mntns_id;
	u64 uid_gid;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct tuple_key_t);
	__type(value, struct pid_comm_t);
} tuplepid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct sock *);
} sockets SEC(".maps");

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(tracetcp, events, event);

__u8 ip_v6_zero[16] = {
	0,
};

static __always_inline bool fill_tuple(struct tuple_key_t *tuple,
				       struct sock *sk, int family)
{
	struct inet_sock *sockp = (struct inet_sock *)sk;

	BPF_CORE_READ_INTO(&tuple->netns, sk, __sk_common.skc_net.net, ns.inum);

	switch (family) {
	case AF_INET:
		BPF_CORE_READ_INTO(&tuple->src.addr_raw.v4, sk,
				   __sk_common.skc_rcv_saddr);
		if (tuple->src.addr_raw.v4 == 0)
			return false;

		BPF_CORE_READ_INTO(&tuple->dst.addr_raw.v4, sk,
				   __sk_common.skc_daddr);
		if (tuple->dst.addr_raw.v4 == 0)
			return false;

		break;
	case AF_INET6:
		BPF_CORE_READ_INTO(
			&tuple->src.addr_raw.v6, sk,
			__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		if (__builtin_memcmp(&tuple->src.addr_raw.v6, &ip_v6_zero,
				     sizeof(tuple->src.addr_raw.v6)) == 0)
			return false;
		BPF_CORE_READ_INTO(&tuple->dst.addr_raw.v6, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
		if (__builtin_memcmp(&tuple->dst.addr_raw.v6, &ip_v6_zero,
				     sizeof(tuple->dst.addr_raw.v6)) == 0)
			return false;

		break;
	/* it should not happen but to be sure let's handle this case */
	default:
		return false;
	}

	BPF_CORE_READ_INTO(&tuple->dst.port, sk, __sk_common.skc_dport);
	tuple->dst.port = bpf_ntohs(tuple->dst.port);
	if (tuple->dst.port == 0)
		return false;

	BPF_CORE_READ_INTO(&tuple->src.port, sockp, inet_sport);
	tuple->src.port = bpf_ntohs(tuple->src.port);
	if (tuple->src.port == 0)
		return false;

	return true;
}

static __always_inline void fill_event(struct tuple_key_t *tuple,
				       struct event *event, __u64 pid_tgid,
				       __u64 uid_gid, __u16 family, __u8 type,
				       __u64 mntns_id)
{
	event->timestamp_raw = bpf_ktime_get_boot_ns();
	event->type_raw = type;
	event->pid = pid_tgid >> 32;
	event->tid = (__u32)pid_tgid;
	event->uid = (__u32)uid_gid;
	event->gid = (__u32)(uid_gid >> 32);
	event->src.proto_raw = event->dst.proto_raw = IPPROTO_TCP;
	event->netns_id = tuple->netns;
	event->mntns_id = mntns_id;
	if (family == AF_INET) {
		event->src.addr_raw.v4 = tuple->src.addr_raw.v4;
		event->dst.addr_raw.v4 = tuple->dst.addr_raw.v4;
		event->src.version = event->dst.version = 4;
	} else {
		__builtin_memcpy(event->src.addr_raw.v6, tuple->src.addr_raw.v6,
				 16);
		__builtin_memcpy(event->dst.addr_raw.v6, tuple->dst.addr_raw.v6,
				 16);
		event->src.version = event->dst.version = 6;
	}
	event->src.port = tuple->src.port;
	event->dst.port = tuple->dst.port;
}

/* returns true if the event should be skipped */
static __always_inline bool filter_event(struct sock *sk, __u32 uid, __u32 pid,
					 __u64 mntns_id)
{
	u16 family;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return true;

	if (gadget_should_discard_mntns_id(mntns_id))
		return true;

	if (filter_pid && pid != filter_pid)
		return true;

	if (filter_uid != (uid_t)-1 && uid != filter_uid)
		return true;

	return false;
}

static __always_inline int enter_tcp_connect(struct pt_regs *ctx,
					     struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = pid_tgid;
	__u64 uid_gid = bpf_get_current_uid_gid();
	__u32 uid = uid_gid;
	__u64 mntns_id;

	mntns_id = gadget_get_mntns_id();

	if (filter_event(sk, uid, pid, mntns_id))
		return 0;

	bpf_map_update_elem(&sockets, &tid, &sk, 0);
	return 0;
}

static __always_inline int exit_tcp_connect(struct pt_regs *ctx, int ret,
					    __u16 family)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = pid_tgid;
	__u64 uid_gid = bpf_get_current_uid_gid();
	struct tuple_key_t tuple = {};
	struct pid_comm_t pid_comm = {};
	struct sock **skpp;
	struct sock *sk;

	skpp = bpf_map_lookup_elem(&sockets, &tid);
	if (!skpp)
		return 0;

	if (ret)
		goto end;

	sk = *skpp;

	if (!fill_tuple(&tuple, sk, family))
		goto end;

	pid_comm.pid_tgid = pid_tgid;
	pid_comm.uid_gid = uid_gid;
	pid_comm.mntns_id = gadget_get_mntns_id();
	bpf_get_current_comm(&pid_comm.comm, sizeof(pid_comm.comm));

	bpf_map_update_elem(&tuplepid, &tuple, &pid_comm, 0);

end:
	bpf_map_delete_elem(&sockets, &tid);
	return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(ig_tcp_v4_co_e, struct sock *sk)
{
	return enter_tcp_connect(ctx, sk);
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(ig_tcp_v4_co_x, int ret)
{
	return exit_tcp_connect(ctx, ret, AF_INET);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(ig_tcp_v6_co_e, struct sock *sk)
{
	return enter_tcp_connect(ctx, sk);
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(ig_tcp_v6_co_x, int ret)
{
	return exit_tcp_connect(ctx, ret, AF_INET6);
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(ig_tcp_close, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u64 uid_gid = bpf_get_current_uid_gid();
	__u32 uid = uid_gid;
	struct tuple_key_t tuple = {};
	struct event *event;
	u16 family;
	__u64 mntns_id;

	mntns_id = gadget_get_mntns_id();

	if (filter_event(sk, uid, pid, mntns_id))
		return 0;

	/*
	 * Don't generate close events for connections that were never
	 * established in the first place.
	 */
	u8 oldstate = BPF_CORE_READ(sk, __sk_common.skc_state);
	if (oldstate == TCP_SYN_SENT || oldstate == TCP_SYN_RECV ||
	    oldstate == TCP_NEW_SYN_RECV)
		return 0;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (!fill_tuple(&tuple, sk, family))
		return 0;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	fill_event(&tuple, event, pid_tgid, uid_gid, family, close, mntns_id);
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
};

SEC("kprobe/tcp_set_state")
int BPF_KPROBE(ig_tcp_state, struct sock *sk, int state)
{
	struct tuple_key_t tuple = {};
	struct event *event;
	__u16 family;

	if (state != TCP_ESTABLISHED && state != TCP_CLOSE)
		goto end;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);

	if (!fill_tuple(&tuple, sk, family))
		goto end;

	if (state == TCP_CLOSE)
		goto end;

	struct pid_comm_t *p;
	p = bpf_map_lookup_elem(&tuplepid, &tuple);
	if (!p)
		return 0; /* missed entry */

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		goto end;

	fill_event(&tuple, event, p->pid_tgid, p->uid_gid, family, connect,
		   p->mntns_id);
	__builtin_memcpy(&event->comm, p->comm, sizeof(event->comm));

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

end:
	bpf_map_delete_elem(&tuplepid, &tuple);

	return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(ig_tcp_accept, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u64 uid_gid = bpf_get_current_uid_gid();
	__u32 uid = uid_gid;
	__u16 sport, family;
	struct event *event;
	struct tuple_key_t t = {};
	u64 mntns_id;

	if (!sk)
		return 0;

	mntns_id = gadget_get_mntns_id();

	if (filter_event(sk, uid, pid, mntns_id))
		return 0;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	sport = BPF_CORE_READ(sk, __sk_common.skc_num);

	fill_tuple(&t, sk, family);
	/* do not send event if IP address is 0.0.0.0 or port is 0 */
	if (__builtin_memcmp(t.src.addr_raw.v6, ip_v6_zero,
			     sizeof(t.src.addr_raw.v6)) == 0 ||
	    __builtin_memcmp(t.dst.addr_raw.v6, ip_v6_zero,
			     sizeof(t.dst.addr_raw.v6)) == 0 ||
	    t.dst.port == 0 || t.src.port == 0)
		return 0;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	fill_event(&t, event, pid_tgid, uid_gid, family, accept, mntns_id);
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
