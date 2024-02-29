// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 The Inspektor Gadget authors */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <stdbool.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GADGET_TYPE_NETWORKING
#include <gadget/sockets-map.h>

#include "dns-common.h"

#define DNS_OFF (ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr))

#ifndef PACKET_HOST
#define PACKET_HOST 0x0
#endif

#ifndef PACKET_OUTGOING
#define PACKET_OUTGOING 0x4
#endif

#define DNS_QR_QUERY 0
#define DNS_QR_RESP 1

#define MAX_PORTS 16
const volatile __u16 ports[MAX_PORTS] = { 53, 5353 };
const volatile __u16 ports_len = 2;

static __always_inline bool is_dns_port(__u16 port)
{
	for (int i = 0; i < ports_len; i++) {
		if (ports[i] == port)
			return true;
	}
	return false;
}

// we need this to make sure the compiler doesn't remove our struct
const struct event_t *unusedevent __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
union dnsflags {
	struct {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		__u8 rcode : 4; // response code
		__u8 z : 3; // reserved
		__u8 ra : 1; // recursion available
		__u8 rd : 1; // recursion desired
		__u8 tc : 1; // truncation
		__u8 aa : 1; // authoritive answer
		__u8 opcode : 4; // kind of query
		__u8 qr : 1; // 0=query; 1=response
#elif __BYTE_ORDER == __ORDER_BIG_ENDIAN__
		__u8 qr : 1; // 0=query; 1=response
		__u8 opcode : 4; // kind of query
		__u8 aa : 1; // authoritive answer
		__u8 tc : 1; // truncation
		__u8 rd : 1; // recursion desired
		__u8 ra : 1; // recursion available
		__u8 z : 3; // reserved
		__u8 rcode : 4; // response code
#else
#error "Fix your compiler's __BYTE_ORDER__?!"
#endif
	};
	__u16 flags;
};

struct dnshdr {
	__u16 id;

	union dnsflags flags;

	__u16 qdcount; // number of question entries
	__u16 ancount; // number of answer entries
	__u16 nscount; // number of authority records
	__u16 arcount; // number of additional records
};

// Map of DNS query to timestamp so we can calculate latency from query sent to answer received.
struct query_key_t {
	__u64 pid_tgid;
	__u16 id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct query_key_t);
	__type(value, __u64); // timestamp of the query
	__uint(max_entries, 1024);
} query_map SEC(".maps");

SEC("socket1")
int ig_trace_dns(struct __sk_buff *skb)
{
	struct event_t event;
	__u16 sport, dport;
	__u16 id;
	int i;

	// Skip non-IP packets
	if (load_half(skb, offsetof(struct ethhdr, h_proto)) != ETH_P_IP)
		return 0;

	// Skip non-UDP packets
	if (load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol)) !=
	    IPPROTO_UDP)
		return 0;

	sport = load_half(skb, ETH_HLEN + sizeof(struct iphdr) +
				       offsetof(struct udphdr, source));
	dport = load_half(skb, ETH_HLEN + sizeof(struct iphdr) +
				       offsetof(struct udphdr, dest));

	if (!is_dns_port(sport) && !is_dns_port(dport))
		return 0;

	// Initialize event here only after we know we're interested in this packet to avoid
	// spending useless cycles.
	__builtin_memset(&event, 0, sizeof(event));

	event.netns = skb->cb[0]; // cb[0] initialized by dispatcher.bpf.c
	event.timestamp = bpf_ktime_get_boot_ns();
	event.pkt_type = skb->pkt_type;

	event.af = AF_INET;
	event.daddr_v4 =
		load_word(skb, ETH_HLEN + offsetof(struct iphdr, daddr));
	event.saddr_v4 =
		load_word(skb, ETH_HLEN + offsetof(struct iphdr, saddr));
	// load_word converts from network to host endianness. Convert back to
	// network endianness because inet_ntop() requires it.
	event.daddr_v4 = bpf_htonl(event.daddr_v4);
	event.saddr_v4 = bpf_htonl(event.saddr_v4);

	event.proto = IPPROTO_UDP;
	event.sport = sport;
	event.dport = dport;

	// Enrich event with process metadata
	struct sockets_value *skb_val = gadget_socket_lookup(skb);
	if (skb_val != NULL) {
		event.mount_ns_id = skb_val->mntns;
		event.pid = skb_val->pid_tgid >> 32;
		event.tid = (__u32)skb_val->pid_tgid;
		__builtin_memcpy(&event.task, skb_val->task,
				 sizeof(event.task));
		event.uid = (__u32)skb_val->uid_gid;
		event.gid = (__u32)(skb_val->uid_gid >> 32);
	}

	// Calculate latency:
	//
	// Track the latency from when a query is sent from a container
	// to when a response to the query is received by that same container.
	//
	// * On DNS query sent from a container namespace (qr == DNS_QR_QUERY and pkt_type == OUTGOING),
	//   store the query timestamp in a map.
	//
	// * On DNS response received in the same container namespace (qr == DNS_QR_RESP and pkt_type == HOST)
	//   retrieve/delete the query timestamp and set the latency field on the event.
	//
	// A garbage collection thread running in userspace periodically scans for keys with old timestamps
	// to free space occupied by queries that never receive a response.
	//
	// Skip this if skb_val == NULL (gadget_socket_lookup did not set pid_tgid we use in the query key)
	// or if event->timestamp == 0 (kernels before 5.8 don't support bpf_ktime_get_boot_ns, and the patched
	// version IG injects always returns zero).
	if (skb_val != NULL && event.timestamp > 0) {
		union dnsflags flags;
		flags.flags = load_half(skb, DNS_OFF + offsetof(struct dnshdr,
								flags));
		id = load_half(skb, DNS_OFF + offsetof(struct dnshdr, id));
		__u8 qr = flags.qr;

		struct query_key_t query_key = {
			.pid_tgid = skb_val->pid_tgid,
			.id = id,
		};
		if (qr == DNS_QR_QUERY && event.pkt_type == PACKET_OUTGOING) {
			bpf_map_update_elem(&query_map, &query_key,
					    &event.timestamp, BPF_NOEXIST);
		} else if (flags.qr == DNS_QR_RESP &&
			   event.pkt_type == PACKET_HOST) {
			__u64 *query_ts =
				bpf_map_lookup_elem(&query_map, &query_key);
			if (query_ts != NULL) {
				// query ts should always be less than the event ts, but check anyway to be safe.
				if (*query_ts < event.timestamp) {
					event.latency_ns =
						event.timestamp - *query_ts;
				}
				bpf_map_delete_elem(&query_map, &query_key);
			}
		}
	}

	__u64 skb_len = skb->len;
	bpf_perf_event_output(skb, &events, skb_len << 32 | BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

	return 0;
}

char _license[] SEC("license") = "GPL";
