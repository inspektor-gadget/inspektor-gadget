// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Francis Laniel <flaniel@linux.microsoft.com>
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include <gadget/filter.h>
#include <gadget/types.h>
#include <gadget/macros.h>
#include <gadget/sockets.h>

/* Taken from kernel include/linux/socket.h. */
#define AF_INET 2 /* Internet IP Protocol 	*/
#define AF_INET6 10 /* IP version 6			*/

const volatile int target_family = -1;
GADGET_PARAM(target_family);

struct ip_key_t {
	gadget_mntns_id mntns_id;
	gadget_pid pid;
	gadget_tid tid;

	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;
	gadget_comm comm[TASK_COMM_LEN];
};

struct traffic_t {
	gadget_bytes sent_raw;
	gadget_bytes received_raw;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct ip_key_t);
	__type(value, struct traffic_t);
} ip_map SEC(".maps");

GADGET_MAPITER(tcp, ip_map);

static int probe_ip(bool receiving, struct sock *sk, size_t size)
{
	struct ip_key_t ip_key = {};
	struct traffic_t *trafficp;
	__u64 mntns_id;
	__u16 family;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = pid_tgid;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (target_family != -1 && ((target_family == 4 && family != AF_INET) ||
				    (target_family == 6 && family != AF_INET6)))
		return 0;

	/* drop */
	if (family != AF_INET && family != AF_INET6)
		return 0;

	if (gadget_should_discard_data_current())
		return 0;

	mntns_id = gadget_get_current_mntns_id();

	ip_key.pid = pid;
	ip_key.tid = tid;
	ip_key.mntns_id = mntns_id;
	bpf_get_current_comm(&ip_key.comm, sizeof(ip_key.comm));
	gadget_l4endpoints_from_sock(&ip_key.src, &ip_key.dst, sk);

	trafficp = bpf_map_lookup_elem(&ip_map, &ip_key);
	if (!trafficp) {
		struct traffic_t zero;

		if (receiving) {
			zero.sent_raw = 0;
			zero.received_raw = size;
		} else {
			zero.sent_raw = size;
			zero.received_raw = 0;
		}

		bpf_map_update_elem(&ip_map, &ip_key, &zero, BPF_NOEXIST);
	} else {
		if (receiving)
			__sync_fetch_and_add(&trafficp->received_raw, size);
		else
			__sync_fetch_and_add(&trafficp->sent_raw, size);
	}

	return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(ig_toptcp_sdmsg, struct sock *sk, struct msghdr *msg,
	       size_t size)
{
	return probe_ip(false, sk, size);
}

/*
 * tcp_recvmsg() would be obvious to trace, but is less suitable because:
 * - we'd need to trace both entry and return, to have both sock and size
 * - misses tcp_read_sock() traffic
 * we'd much prefer tracepoints once they are available.
 */
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(ig_toptcp_clean, struct sock *sk, int copied)
{
	if (copied <= 0)
		return 0;

	return probe_ip(true, sk, copied);
}

char LICENSE[] SEC("license") = "GPL";
