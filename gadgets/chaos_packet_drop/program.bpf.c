// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Microsoft Corporation

#include <vmlinux.h>

#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/
#define ETH_P_IPV6 0x86DD /* IPv6 over bluebook		*/

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_UNSPEC -1

#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <gadget/types.h>
#include <gadget/macros.h>
#include <gadget/buffer.h>
#include <gadget/common.h>

#define GADGET_TYPE_NETWORKING
#include <gadget/sockets-map.h>

/* The maximum number of items in maps */
#define MAX_ENTRIES 8192
#define TASK_COMM_LEN 16

struct events_map_key {
	struct gadget_l4endpoint_t external_l4endpoint;
};

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_l4endpoint_t host_l4enpoint;
	gadget_counter__u32 drop_cnt;
	bool ingress;
	bool egress;

	gadget_netns_id netns_id;
	struct gadget_process proc;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	// The key is going to be L4 gadget endpoint
	__type(key, struct events_map_key);
	__type(value, struct event);
} events_map SEC(".maps");

GADGET_MAPITER(events_map_iter, events_map);

// we use the following variables as parameters
const volatile struct gadget_l3endpoint_t filter_ip = { 0 };
const volatile __u16 port = 0;
const volatile __u32 loss_percentage = 100;

/* This is a boolean flag to enable filtering of TCP packets */
const volatile bool filter_tcp = true;

/* This is a boolean flag to enable filtering of UDP packets */
const volatile bool filter_udp = true;

/* This is a boolean flag to enable filtering of ingress packets */
const volatile bool ingress = false;

/* This is a boolean flag to enable filtering of egress packets */
const volatile bool egress = true;

GADGET_PARAM(filter_ip);
GADGET_PARAM(port);
GADGET_PARAM(loss_percentage);
GADGET_PARAM(filter_tcp);
GADGET_PARAM(filter_udp);
GADGET_PARAM(ingress);
GADGET_PARAM(egress);

/* This function drops packets based on independent (Bernoulli) probability model 
where each packet is dropped with an independent probabilty for dropping packets */
static int rand_pkt_drop_map_update(struct event *event,
				    struct events_map_key *key,
				    struct __sk_buff *skb)
{
	// Get a random 32-bit unsigned integer
	__u32 rand_num = bpf_get_prandom_u32();
	// Set the threshold using the loss_percentage = loss_percentage% of UINT32_MAX
	volatile __u64 threshold =
		(volatile __u64)((volatile __u64)loss_percentage *
				 (__u64)0xFFFFFFFF) /
		100;

	// Run the code only if the random number is less than the threshold
	if (rand_num <= (u32)threshold) {
		/* The events which are stored in the events_map */
		struct event *event_map_val =
			bpf_map_lookup_elem(&events_map, key);
		if (!event_map_val) {
			event->egress = egress;
			event->ingress = ingress;
			event->drop_cnt = 1;

			// Enrich event with process metadata
			struct sockets_value *skb_val =
				gadget_socket_lookup(skb);
			if (skb_val != NULL)
				gadget_process_populate_from_socket(
					skb_val, &event->proc);
			event->timestamp_raw = bpf_ktime_get_boot_ns();
			bpf_map_update_elem(&events_map, key, event,
					    BPF_NOEXIST);
		} else {
			// Increment the the value of drop count by 1.
			// We use sync fetch and add which is an atomic addition operation
			__sync_fetch_and_add(&event_map_val->drop_cnt, 1);
			event_map_val->timestamp_raw = bpf_ktime_get_boot_ns();
			;
		}
		return TC_ACT_SHOT;
	}
	return TC_ACT_OK;
}

static __always_inline void read_ipv6_address(struct event *event,
					      struct events_map_key *key,
					      struct ipv6hdr *ip6h)
{
	bpf_probe_read_kernel(event->host_l4enpoint.addr_raw.v6,
			      sizeof(event->host_l4enpoint.addr_raw.v6),
			      ip6h->saddr.in6_u.u6_addr8);
	bpf_probe_read_kernel(key->external_l4endpoint.addr_raw.v6,
			      sizeof(key->external_l4endpoint.addr_raw.v6),
			      ip6h->daddr.in6_u.u6_addr8);
}

// Helper to parse L4 headers (TCP/UDP)
static __always_inline int parse_l4(struct __sk_buff *skb, void *l4_ptr,
				    int proto, bool at_egress, __u16 hns_port,
				    struct event *event,
				    struct events_map_key *key, void *data_end)
{
	struct tcphdr *tcph;
	struct udphdr *udph;

	switch (proto) {
	case IPPROTO_TCP:
		if (!filter_tcp)
			return TC_ACT_OK;

		tcph = (struct tcphdr *)l4_ptr;
		if ((void *)(tcph + 1) > data_end)
			return TC_ACT_OK;

		if (!at_egress && hns_port != 0 && hns_port != tcph->source)
			return TC_ACT_OK;
		if (at_egress && hns_port != 0 && hns_port != tcph->dest)
			return TC_ACT_OK;

		event->host_l4enpoint.proto_raw =
			key->external_l4endpoint.proto_raw = IPPROTO_TCP;
		event->host_l4enpoint.port = bpf_ntohs(tcph->source);
		key->external_l4endpoint.port = at_egress ?
							bpf_ntohs(tcph->dest) :
							bpf_ntohs(tcph->source);
		break;

	case IPPROTO_UDP:
		if (!filter_udp)
			return TC_ACT_OK;

		udph = (struct udphdr *)l4_ptr;
		if ((void *)(udph + 1) > data_end)
			return TC_ACT_OK;

		if (!at_egress && hns_port != 0 && hns_port != udph->source)
			return TC_ACT_OK;
		if (at_egress && hns_port != 0 && hns_port != udph->dest)
			return TC_ACT_OK;

		event->host_l4enpoint.proto_raw =
			key->external_l4endpoint.proto_raw = IPPROTO_UDP;
		event->host_l4enpoint.port = bpf_ntohs(udph->source);
		key->external_l4endpoint.port = at_egress ?
							bpf_ntohs(udph->dest) :
							bpf_ntohs(udph->source);
		break;

	default:
		return TC_ACT_OK;
	}

	return TC_ACT_UNSPEC; // Continue processing
}

static __always_inline int packet_drop(struct __sk_buff *skb, bool at_egress)
{
	/* This is the key for events_map -> being the target addr,port pair */
	struct events_map_key key;

	/* The struct to store the information regarding the event */
	struct event event;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	struct iphdr *ip4h;
	struct ipv6hdr *ip6h;
	void *l4_ptr = NULL;

	/* Check if the ethernet headers are invalid if so ignore 
	   the packets, else do the further processing	 */
	if ((void *)(eth + 1) > data_end) {
		return TC_ACT_OK;
	}

	switch (bpf_ntohs(eth->h_proto)) {
	default:
		// Unhandled protocol, pass through
		return TC_ACT_OK;

	// IPv4 Processing
	case ETH_P_IP:
		if (filter_ip.version == 6)
			return TC_ACT_OK;

		ip4h = (struct iphdr *)(eth + 1);
		if ((void *)(ip4h + 1) > data_end)
			return TC_ACT_OK;

		if (!at_egress && filter_ip.addr_raw.v4 != 0 &&
		    filter_ip.addr_raw.v4 != ip4h->saddr)
			return TC_ACT_OK;
		if (at_egress && filter_ip.addr_raw.v4 != 0 &&
		    filter_ip.addr_raw.v4 != ip4h->daddr)
			return TC_ACT_OK;

		event.host_l4enpoint.version = key.external_l4endpoint.version =
			4;
		event.host_l4enpoint.addr_raw.v4 = at_egress ? ip4h->saddr :
							       ip4h->daddr;
		key.external_l4endpoint.addr_raw.v4 = at_egress ? ip4h->daddr :
								  ip4h->saddr;

		l4_ptr = (__u8 *)ip4h + (ip4h->ihl * 4);
		if (parse_l4(skb, l4_ptr, ip4h->protocol, at_egress,
			     bpf_htons(port), &event, &key,
			     data_end) != TC_ACT_UNSPEC)
			return TC_ACT_OK;
		break;

	case ETH_P_IPV6:
		if (filter_ip.version == 4 && filter_ip.addr_raw.v4 != 0)
			return TC_ACT_OK;

		ip6h = (struct ipv6hdr *)(eth + 1);
		if ((void *)(ip6h + 1) > data_end)
			return TC_ACT_OK;

		if (ingress && filter_ip.version == 6 &&
		    __builtin_memcmp(filter_ip.addr_raw.v6,
				     ip6h->saddr.in6_u.u6_addr8, 16))
			return TC_ACT_OK;
		if (egress && filter_ip.version == 6 &&
		    __builtin_memcmp(filter_ip.addr_raw.v6,
				     ip6h->daddr.in6_u.u6_addr8, 16))
			return TC_ACT_OK;

		read_ipv6_address(&event, &key, ip6h);
		event.host_l4enpoint.version = key.external_l4endpoint.version =
			6;

		l4_ptr = (__u8 *)ip6h + sizeof(struct ipv6hdr);
		if (parse_l4(skb, l4_ptr, ip6h->nexthdr, at_egress,
			     bpf_htons(port), &event, &key,
			     data_end) != TC_ACT_UNSPEC)
			return TC_ACT_OK;
		break;
	}

	/* 	cb[0] initialized by dispatcher.bpf.c to get the netns_id*/
	event.netns_id = skb->cb[0];
	event.proc.comm[0] = '\0';
	event.proc.parent.comm[0] = '\0';

	return rand_pkt_drop_map_update(&event, &key, skb);
}

SEC("classifier/egress/drop")
int egress_pkt_drop(struct __sk_buff *skb)
{
	if (egress)
		return packet_drop(skb, true);
	else
		return TC_ACT_OK;
}

/* Extremly similar to egress */
SEC("classifier/ingress/drop")
int ingress_pkt_drop(struct __sk_buff *skb)
{
	if (ingress)
		return packet_drop(skb, false);
	else
		return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";