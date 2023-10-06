// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Anton Protopopov
//
// Based on tcpconnect(8) from BCC by Brendan Gregg
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include <gadget/macros.h>
#include <gadget/maps.bpf.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

/* The maximum number of items in maps */
#define MAX_ENTRIES 8192

/* The maximum number of ports to filter */
#define MAX_PORTS 64

struct ipv4_flow_key {
	__u32 saddr;
	__u32 daddr;
	__u16 dport;
};

struct ipv6_flow_key {
	__u8 saddr[16];
	__u8 daddr[16];
	__u16 dport;
};

struct event {
	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;

	__u8 task[TASK_COMM_LEN];
	__u64 timestamp;
	__u32 pid;
	__u32 uid;
	__u32 gid;
	mnt_ns_id_t mntns_id;
	__u64 latency;
};

const volatile int filter_ports[MAX_PORTS];
const volatile int filter_ports_len = 0;
const volatile uid_t filter_uid = -1;
const volatile pid_t filter_pid = 0;
const volatile bool do_count = 0;
const volatile bool calculate_latency = false;
const volatile __u64 targ_min_latency_ns = 0;

/* Define here, because there are conflicts with include files */
#define AF_INET 2
#define AF_INET6 10

// we need this to make sure the compiler doesn't remove our struct
const struct event *unusedevent __attribute__((unused));

// sockets_per_process keeps track of the sockets between:
// - kprobe enter_tcp_connect
// - kretprobe exit_tcp_connect
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // tid
	__type(value, struct sock *);
} sockets_per_process SEC(".maps");

struct piddata {
	char comm[TASK_COMM_LEN];
	u64 ts;
	u32 pid;
	u32 tid;
	u64 mntns_id;
};

// sockets_latency keeps track of sockets to calculate the latency between:
// - enter_tcp_connect (where the socket is added in the map)
// - handle_tcp_rcv_state_process (where the socket is removed from the map)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct sock *);
	__type(value, struct piddata);
} sockets_latency SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct ipv4_flow_key);
	__type(value, u64);
} ipv4_count SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct ipv6_flow_key);
	__type(value, u64);
} ipv6_count SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__type(value, struct event);
} events SEC(".maps");

GADGET_TRACE_MAP(events);

static __always_inline bool filter_port(__u16 port)
{
	int i;

	if (filter_ports_len == 0)
		return false;

	// This loop was written a bit different than the upstream one
	// to avoid a verifier error.
	for (i = 0; i < MAX_PORTS; i++) {
		if (i >= filter_ports_len)
			break;
		if (port == filter_ports[i])
			return false;
	}
	return true;
}

static __always_inline int enter_tcp_connect(struct pt_regs *ctx,
					     struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = pid_tgid;
	__u64 mntns_id;
	__u32 uid = (u32)uid_gid;
	;
	struct piddata piddata = {};

	if (filter_pid && pid != filter_pid)
		return 0;

	if (filter_uid != (uid_t)-1 && uid != filter_uid)
		return 0;

	mntns_id = gadget_get_mntns_id();

	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	if (calculate_latency) {
		bpf_get_current_comm(&piddata.comm, sizeof(piddata.comm));
		piddata.ts = bpf_ktime_get_ns();
		piddata.tid = tid;
		piddata.pid = pid;
		piddata.mntns_id = mntns_id;
		bpf_map_update_elem(&sockets_latency, &sk, &piddata, 0);
	} else {
		bpf_map_update_elem(&sockets_per_process, &tid, &sk, 0);
	}
	return 0;
}

static __always_inline void count_v4(struct sock *sk, __u16 dport)
{
	struct ipv4_flow_key key = {};
	static __u64 zero;
	__u64 *val;

	BPF_CORE_READ_INTO(&key.saddr, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&key.daddr, sk, __sk_common.skc_daddr);
	key.dport = dport;
	val = bpf_map_lookup_or_try_init(&ipv4_count, &key, &zero);
	if (val)
		__atomic_add_fetch(val, 1, __ATOMIC_RELAXED);
}

static __always_inline void count_v6(struct sock *sk, __u16 dport)
{
	struct ipv6_flow_key key = {};
	static const __u64 zero;
	__u64 *val;

	BPF_CORE_READ_INTO(&key.saddr, sk,
			   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	BPF_CORE_READ_INTO(&key.daddr, sk,
			   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	key.dport = dport;

	val = bpf_map_lookup_or_try_init(&ipv6_count, &key, &zero);
	if (val)
		__atomic_add_fetch(val, 1, __ATOMIC_RELAXED);
}

static __always_inline void trace_v4(struct pt_regs *ctx, pid_t pid,
				     struct sock *sk, __u16 dport,
				     __u64 mntns_id)
{
	struct event event = {};

	__u64 uid_gid = bpf_get_current_uid_gid();

	event.pid = pid;
	event.uid = (u32)uid_gid;
	event.gid = (u32)(uid_gid >> 32);
	event.src.l3.version = event.dst.l3.version = 4;
	event.src.proto = event.dst.proto = IPPROTO_TCP;
	BPF_CORE_READ_INTO(&event.src.l3.addr.v4, sk,
			   __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&event.dst.l3.addr.v4, sk, __sk_common.skc_daddr);
	event.dst.port =
		bpf_ntohs(dport); // host expects data in host byte order
	event.src.port = BPF_CORE_READ(sk, __sk_common.skc_num);
	event.mntns_id = mntns_id;
	bpf_get_current_comm(event.task, sizeof(event.task));
	event.timestamp = bpf_ktime_get_boot_ns();

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
			      sizeof(event));
}

static __always_inline void trace_v6(struct pt_regs *ctx, pid_t pid,
				     struct sock *sk, __u16 dport,
				     __u64 mntns_id)
{
	struct event event = {};

	__u64 uid_gid = bpf_get_current_uid_gid();

	event.pid = pid;
	event.uid = (u32)uid_gid;
	event.gid = (u32)(uid_gid >> 32);
	event.mntns_id = mntns_id;
	event.src.l3.version = event.dst.l3.version = 6;
	event.src.proto = event.dst.proto = IPPROTO_TCP;
	BPF_CORE_READ_INTO(&event.src.l3.addr.v6, sk,
			   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	BPF_CORE_READ_INTO(&event.dst.l3.addr.v6, sk,
			   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	event.dst.port =
		bpf_ntohs(dport); // host expects data in host byte order
	event.src.port = BPF_CORE_READ(sk, __sk_common.skc_num);
	bpf_get_current_comm(event.task, sizeof(event.task));
	event.timestamp = bpf_ktime_get_boot_ns();

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
			      sizeof(event));
}

static __always_inline int exit_tcp_connect(struct pt_regs *ctx, int ret,
					    int ip_ver)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = pid_tgid;
	struct sock **skpp;
	struct sock *sk;
	u64 mntns_id;
	__u16 dport;

	skpp = bpf_map_lookup_elem(&sockets_per_process, &tid);
	if (!skpp)
		return 0;

	if (ret)
		goto end;

	sk = *skpp;

	BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
	if (filter_port(dport))
		goto end;

	if (do_count) {
		if (ip_ver == 4)
			count_v4(sk, dport);
		else
			count_v6(sk, dport);
	} else {
		mntns_id = gadget_get_mntns_id();

		if (ip_ver == 4)
			trace_v4(ctx, pid, sk, dport, mntns_id);
		else
			trace_v6(ctx, pid, sk, dport, mntns_id);
	}

end:
	bpf_map_delete_elem(&sockets_per_process, &tid);
	return 0;
}

static __always_inline int cleanup_sockets_latency_map(const struct sock *sk)
{
	bpf_map_delete_elem(&sockets_latency, &sk);
	return 0;
}

static __always_inline int handle_tcp_rcv_state_process(void *ctx,
							struct sock *sk)
{
	struct piddata *piddatap;
	struct event event = {};
	unsigned int family;
	u64 ts;

	if (BPF_CORE_READ(sk, __sk_common.skc_state) != TCP_SYN_SENT)
		return 0;

	piddatap = bpf_map_lookup_elem(&sockets_latency, &sk);
	if (!piddatap)
		return 0;

	ts = bpf_ktime_get_ns();
	if (ts < piddatap->ts)
		goto cleanup;

	event.latency = ts - piddatap->ts;
	if (targ_min_latency_ns && event.latency < targ_min_latency_ns)
		goto cleanup;
	__builtin_memcpy(&event.task, piddatap->comm, sizeof(event.task));
	event.pid = piddatap->pid;
	event.mntns_id = piddatap->mntns_id;
	event.src.port = BPF_CORE_READ(sk, __sk_common.skc_num);
	// host expects data in host byte order
	event.dst.port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	event.src.proto = event.dst.proto = IPPROTO_TCP;
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family == AF_INET) {
		event.src.l3.version = event.dst.l3.version = 4;
		event.src.l3.addr.v4 =
			BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		event.dst.l3.addr.v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	} else {
		event.src.l3.version = event.dst.l3.version = 6;
		BPF_CORE_READ_INTO(
			&event.src.l3.addr.v6, sk,
			__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&event.dst.l3.addr.v6, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}
	event.timestamp = bpf_ktime_get_boot_ns();
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
			      sizeof(event));

cleanup:
	return cleanup_sockets_latency_map(sk);
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(ig_tcpc_v4_co_e, struct sock *sk)
{
	return enter_tcp_connect(ctx, sk);
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(ig_tcpc_v4_co_x, int ret)
{
	return exit_tcp_connect(ctx, ret, 4);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(ig_tcpc_v6_co_e, struct sock *sk)
{
	return enter_tcp_connect(ctx, sk);
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(ig_tcpc_v6_co_x, int ret)
{
	return exit_tcp_connect(ctx, ret, 6);
}

SEC("kprobe/tcp_rcv_state_process")
int BPF_KPROBE(ig_tcp_rsp, struct sock *sk)
{
	return handle_tcp_rcv_state_process(ctx, sk);
}

// tcp_destroy_sock is fired for ipv4 and ipv6.
SEC("tracepoint/tcp/tcp_destroy_sock")
int ig_tcp_destroy(struct trace_event_raw_tcp_event_sk *ctx)
{
	return cleanup_sockets_latency_map(ctx->skaddr);
}

char LICENSE[] SEC("license") = "GPL";
