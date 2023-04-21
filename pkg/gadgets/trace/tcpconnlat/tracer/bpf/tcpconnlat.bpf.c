// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "tcpconnlat.h"

#define AF_INET    2
#define AF_INET6   10

// we need this to make sure the compiler doesn't remove our struct
const struct event *unusedevent __attribute__((unused));

const volatile __u64 targ_min_ns = 0;
const volatile pid_t targ_tgid = 0;
const volatile bool filter_by_mnt_ns = false;

struct piddata {
	char comm[TASK_COMM_LEN];
	u64 ts;
	u32 tgid;
	u32 pid;
	u64 mntns_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct sock *);
	__type(value, struct piddata);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(u32));
} mount_ns_filter SEC(".maps");

static __always_inline int trace_connect(struct sock *sk)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid >> 32;
	u32 pid = (u32)pid_tgid;
	struct piddata piddata = {};
	struct task_struct *task;
	u64 mntns_id;

	if (targ_tgid && targ_tgid != tgid)
		return 0;

	task = (struct task_struct*)bpf_get_current_task();
	mntns_id = (u64) BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

	if (filter_by_mnt_ns && !bpf_map_lookup_elem(&mount_ns_filter, &mntns_id))
		return 0;

	bpf_get_current_comm(&piddata.comm, sizeof(piddata.comm));
	piddata.ts = bpf_ktime_get_ns();
	piddata.tgid = tgid;
	piddata.pid = pid;
	piddata.mntns_id = mntns_id;
	bpf_map_update_elem(&start, &sk, &piddata, 0);
	return 0;
}

static __always_inline int cleanup_sock(struct sock *sk)
{
	bpf_map_delete_elem(&start, &sk);
	return 0;
}

static __always_inline int handle_tcp_rcv_state_process(void *ctx, struct sock *sk)
{
	struct piddata *piddatap;
	struct event event = {};
	u64 ts;

	if (BPF_CORE_READ(sk, __sk_common.skc_state) != TCP_SYN_SENT)
		return 0;

	piddatap = bpf_map_lookup_elem(&start, &sk);
	if (!piddatap)
		return 0;

	ts = bpf_ktime_get_ns();
	if (ts < piddatap->ts)
		goto cleanup;

	event.delta = ts - piddatap->ts;
	if (targ_min_ns && event.delta < targ_min_ns)
		goto cleanup;
	__builtin_memcpy(&event.comm, piddatap->comm,
			sizeof(event.comm));
	event.tgid = piddatap->tgid;
	event.pid = piddatap->pid;
	event.mntns_id = piddatap->mntns_id;
	event.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	event.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	event.af = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (event.af == AF_INET) {
		event.saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		event.daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	} else {
		BPF_CORE_READ_INTO(&event.saddr_v6, sk,
				__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&event.daddr_v6, sk,
				__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}
	event.timestamp = bpf_ktime_get_boot_ns();
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			&event, sizeof(event));

cleanup:
	return cleanup_sock(sk);
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(ig_tcpc_v4_co_e, struct sock *sk)
{
	return trace_connect(sk);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(ig_tcpc_v6_co_e, struct sock *sk)
{
	return trace_connect(sk);
}

SEC("kprobe/tcp_rcv_state_process")
int BPF_KPROBE(ig_tcp_rsp, struct sock *sk)
{
	return handle_tcp_rcv_state_process(ctx, sk);
}

SEC("kprobe/tcp_v4_destroy_sock")
int BPF_KPROBE(ig_tcp4_destroy, struct sock *sk)
{
	return cleanup_sock(sk);
}

SEC("kprobe/tcp_v6_destroy_sock")
int BPF_KPROBE(ig_tcp6_destroy, struct sock *sk)
{
	return cleanup_sock(sk);
}

// Enable once https://github.com/inspektor-gadget/inspektor-gadget/issues/1566 is fixed.
//SEC("fentry/tcp_v4_connect")
//int BPF_PROG(fentry_tcp_v4_connect, struct sock *sk)
//{
//	return trace_connect(sk);
//}
//
//SEC("fentry/tcp_v6_connect")
//int BPF_PROG(fentry_tcp_v6_connect, struct sock *sk)
//{
//	return trace_connect(sk);
//}
//
//SEC("fentry/tcp_rcv_state_process")
//int BPF_PROG(fentry_tcp_rcv_state_process, struct sock *sk)
//{
//	return handle_tcp_rcv_state_process(ctx, sk);
//}
//
//SEC("fentry/tcp_v4_destroy_sock")
//int BPF_PROG(fentry_tcp_v4_destroy_sock, struct sock *sk)
//{
//	return cleanup_sock(sk);
//}
//
//SEC("fentry/tcp_v6_destroy_sock")
//int BPF_PROG(fentry_tcp_v6_destroy_sock, struct sock *sk)
//{
//	return cleanup_sock(sk);
//}

char LICENSE[] SEC("license") = "GPL";
