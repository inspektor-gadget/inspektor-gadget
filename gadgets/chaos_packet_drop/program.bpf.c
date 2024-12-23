// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Microsoft Corporation

#include <vmlinux.h>

/* I am directly including the 
value of the constants instead of 
the linux/if_ether.h header file and linux/pkt_cls.h
because of redeclaration conflicts with
vmlinux.h */

#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/
#define ETH_P_IPV6 0x86DD /* IPv6 over bluebook		*/

#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_RECLASSIFY 1
#define TC_ACT_SHOT 2
#define TC_ACT_PIPE 3
#define TC_ACT_STOLEN 4
#define TC_ACT_QUEUED 5
#define TC_ACT_REPEAT 6
#define TC_ACT_REDIRECT 7

#include <stdbool.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <gadget/types.h>
#include <gadget/macros.h>
#include <gadget/buffer.h>

#define GADGET_TYPE_NETWORKING
#include <gadget/sockets-map.h>

/* The maximum number of items in maps */
#define MAX_ENTRIES 8192
#define TASK_COMM_LEN 16

struct events_map_key {
	struct gadget_l4endpoint_t dst;
};

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_l4endpoint_t src;
	gadget_counter__u32 drop_cnt;
	bool ingress;
	bool egress;

	gadget_netns_id netns_id;
	struct gadget_process proc;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key,
	       struct events_map_key); // The key is going to be L4 gadget endpoint
	__type(value, struct event);
} events_map SEC(".maps");

GADGET_MAPITER(events_map_iter, events_map);

// we use the following variables as parameters
const volatile struct gadget_l3endpoint_t filter_ip = { 0 };
const volatile __u16 port = 0;
const volatile __u32 loss_percentage = 100;
const volatile bool filter_tcp =
	true; /* This is a boolean flag to enable filtering of TCP packets */
const volatile bool filter_udp =
	true; /* This is a boolean flag to enable filtering of UDP packets */
const volatile bool ingress =
	false; /* This is a boolean flag to enable filtering of ingress packets */
const volatile bool egress =
	true; /* This is a boolean flag to enable filtering of egress packets */

GADGET_PARAM(filter_ip);
GADGET_PARAM(port);
GADGET_PARAM(loss_percentage);
GADGET_PARAM(filter_tcp);
GADGET_PARAM(filter_udp);
GADGET_PARAM(ingress);
GADGET_PARAM(egress);

static __always_inline void swap_src_dst(struct event *event,
					 struct events_map_key *key)
{
	struct gadget_l4endpoint_t temp = event->src;
	event->src = key->dst;
	key->dst = temp;
}

/* This function drops packets based on independent (Bernoulli) probability model 
where each packet is dropped with an independent probabilty for dropping packets */
static int rand_pkt_drop_map_update(struct event *event,
				    struct events_map_key *key,
				    struct sockets_key *sockets_key_for_md)
{
	__u32 rand_num =
		bpf_get_prandom_u32(); // Get a random 32-bit unsigned integer
	// Set the threshold using the loss_percentage
	volatile __u64 threshold =
		(volatile __u64)((volatile __u64)loss_percentage *
				 (__u64)0xFFFFFFFF) /
		100; // loss_percentage% of UINT32_MAX

	if (ingress == true) {
		swap_src_dst(event, key);
	}
	struct event *event_map_val = bpf_map_lookup_elem(
		&events_map,
		key); /* The events which are stored in the events_map */

	if (!event)
		return TC_ACT_OK;

	if (rand_num <=
	    (u32)threshold) // Run the code only if the random number is less than the threshold
	{
		if (!event_map_val) {
			event->egress = egress;
			event->ingress = ingress;
			event->drop_cnt = 1;
			/* Data collection using the socket enricher, we use the key from the map
			to collect information regarding pid, mntns_id, tid, ppid etc */
			sockets_key_for_md->port = key->dst.port;
			struct sockets_value *skb_val = bpf_map_lookup_elem(
				&gadget_sockets, sockets_key_for_md);
			if (skb_val != NULL) {
				event->proc.mntns_id = skb_val->mntns;
				event->proc.pid = skb_val->pid_tgid >> 32;
				event->proc.tid = (__u32)skb_val->pid_tgid;
				event->proc.parent.pid = skb_val->ppid;
				__builtin_memcpy(&event->proc.comm,
						 skb_val->task,
						 sizeof(event->proc.comm));
				__builtin_memcpy(
					&event->proc.parent.comm,
					skb_val->ptask,
					sizeof(event->proc.parent.comm));
				event->proc.creds.uid = (__u32)skb_val->uid_gid;
				event->proc.creds.gid =
					(__u32)(skb_val->uid_gid >> 32);
			}
			event->timestamp_raw = bpf_ktime_get_boot_ns();
			bpf_map_update_elem(&events_map, key, event,
					    BPF_NOEXIST);
		} else {
			// Increment the the value of drop count by 1.
			// We use sync fetch and add which is an atomic addition operation
			__sync_fetch_and_add(&event_map_val->drop_cnt, 1);
			event_map_val->timestamp_raw = bpf_ktime_get_boot_ns();
			bpf_map_update_elem(&events_map, key, event_map_val,
					    BPF_EXIST);
		}
		return TC_ACT_SHOT;
	}
	return TC_ACT_OK;
}

static __always_inline void read_ipv6_address(struct event *event,
					      struct events_map_key *key,
					      struct ipv6hdr *ip6h)
{
	bpf_probe_read_kernel(event->src.addr_raw.v6,
			      sizeof(event->src.addr_raw.v6),
			      ip6h->saddr.in6_u.u6_addr8);
	bpf_probe_read_kernel(key->dst.addr_raw.v6,
			      sizeof(key->dst.addr_raw.v6),
			      ip6h->daddr.in6_u.u6_addr8);
}

static __always_inline int packet_drop(struct __sk_buff *skb)
{
	struct events_map_key
		key; /* This is the key for events_map -> being the target addr,port pair */
	struct sockets_key
		sockets_key_for_md; /* This is for socket enrichement map */
	struct event
		event; /* The struct to store the information regarding the event */

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	struct iphdr *ip4h;
	struct ipv6hdr *ip6h;

	/* Check if the ethernet headers are invalid if so ignore 
	   the packets, else do the further processing	 */
	if ((void *)(eth + 1) > data_end) {
		return TC_ACT_OK; // Eth headers incomplete - Letting them pass through the without further processing
	}

	switch (bpf_ntohs(eth->h_proto)) {
	default:
		return TC_ACT_OK; // Unhandled protocol, pass through
	case ETH_P_IP: // IPv4 Processing
		if (filter_ip.version == 6)
			return TC_ACT_OK; // If filtering IPv6, let IPv4 pass through

		ip4h = (struct iphdr *)(eth + 1);

		/* Check if IPv4 headers are invalid */
		if ((void *)(ip4h + 1) > data_end)
			return TC_ACT_OK;

		if (ingress && filter_ip.addr_raw.v4 != 0 &&
		    (filter_ip.addr_raw.v4 != ip4h->saddr))
			return TC_ACT_OK;
		if (egress && filter_ip.addr_raw.v4 != 0 &&
		    (filter_ip.addr_raw.v4 != ip4h->daddr))
			return TC_ACT_OK;

		event.src.addr_raw.v4 = ip4h->saddr;
		key.dst.addr_raw.v4 = ip4h->daddr;
		event.src.version = key.dst.version = 4;
		sockets_key_for_md.family = SE_AF_INET;

		switch (ip4h->protocol) {
		case IPPROTO_TCP:
			if (!filter_tcp)
				return TC_ACT_OK;
			struct tcphdr *tcph =
				(struct tcphdr *)((__u8 *)ip4h +
						  (ip4h->ihl * 4));
			if ((void *)(tcph + 1) > data_end)
				return TC_ACT_OK;

			if (ingress && port != 0 &&
			    port != bpf_ntohs(tcph->source))
				return TC_ACT_OK;
			if (egress && port != 0 &&
			    port != bpf_ntohs(tcph->dest))
				return TC_ACT_OK;

			event.src.proto_raw = key.dst.proto_raw = IPPROTO_TCP;
			event.src.port = bpf_ntohs(tcph->source);
			key.dst.port = skb->pkt_type == SE_PACKET_HOST ?
					       bpf_ntohs(tcph->dest) :
					       bpf_ntohs(tcph->source);
			sockets_key_for_md.proto = IPPROTO_TCP;
			break;

		case IPPROTO_UDP:
			if (!filter_udp)
				return TC_ACT_OK;
			struct udphdr *udph =
				(struct udphdr *)((__u8 *)ip4h +
						  (ip4h->ihl * 4));
			if ((void *)(udph + 1) > data_end)
				return TC_ACT_OK;

			if (ingress && port != 0 &&
			    port != bpf_ntohs(udph->source))
				return TC_ACT_OK;
			if (egress && port != 0 &&
			    port != bpf_ntohs(udph->dest))
				return TC_ACT_OK;

			event.src.port = bpf_ntohs(udph->source);
			key.dst.port = skb->pkt_type == SE_PACKET_HOST ?
					       bpf_ntohs(udph->dest) :
					       bpf_ntohs(udph->source);
			event.src.proto_raw = key.dst.proto_raw = IPPROTO_UDP;
			sockets_key_for_md.proto = IPPROTO_UDP;
			break;

		default:
			return TC_ACT_OK;
		}
		break;

	case ETH_P_IPV6: // IPv6 Processing
		if (filter_ip.version == 4 && filter_ip.addr_raw.v4 != 0)
			return TC_ACT_OK;

		ip6h = (struct ipv6hdr *)(eth + 1);

		/* Check if IPv6 headers are invalid */
		if ((void *)(ip6h + 1) > data_end)
			return TC_ACT_OK;

		if (ingress && filter_ip.version == 6 &&
		    (__builtin_memcmp((const void *)filter_ip.addr_raw.v6,
				      ip6h->saddr.in6_u.u6_addr8, 16)))
			return TC_ACT_OK;
		if (egress && filter_ip.version == 6 &&
		    (__builtin_memcmp((const void *)filter_ip.addr_raw.v6,
				      ip6h->daddr.in6_u.u6_addr8, 16)))
			return TC_ACT_OK;

		event.src.version = key.dst.version = 6;
		sockets_key_for_md.family = SE_AF_INET6;
		if (ip6h->nexthdr != NULL)
			read_ipv6_address(&event, &key, ip6h);

		switch (ip6h->nexthdr) {
		case IPPROTO_TCP:
			if (!filter_tcp)
				return TC_ACT_OK;
			struct tcphdr *tcph = (struct tcphdr *)(ip6h + 1);
			if ((void *)(tcph + 1) > data_end)
				return TC_ACT_OK;

			if (ingress && port != 0 &&
			    port != bpf_ntohs(tcph->source))
				return TC_ACT_OK;
			if (egress && port != 0 &&
			    port != bpf_ntohs(tcph->dest))
				return TC_ACT_OK;

			event.src.proto_raw = key.dst.proto_raw = IPPROTO_TCP;
			event.src.port = bpf_ntohs(tcph->source);
			key.dst.port = skb->pkt_type == SE_PACKET_HOST ?
					       bpf_ntohs(tcph->dest) :
					       bpf_ntohs(tcph->source);
			sockets_key_for_md.proto = IPPROTO_TCP;
			break;

		case IPPROTO_UDP:
			if (!filter_udp)
				return TC_ACT_OK;
			struct udphdr *udph = (struct udphdr *)(ip6h + 1);
			if ((void *)(udph + 1) > data_end)
				return TC_ACT_OK;

			if (ingress && port != 0 &&
			    port != bpf_ntohs(udph->source))
				return TC_ACT_OK;
			if (egress && port != 0 &&
			    port != bpf_ntohs(udph->dest))
				return TC_ACT_OK;

			event.src.port = bpf_ntohs(udph->source);
			key.dst.port = skb->pkt_type == SE_PACKET_HOST ?
					       bpf_ntohs(udph->dest) :
					       bpf_ntohs(udph->source);
			event.src.proto_raw = key.dst.proto_raw = IPPROTO_UDP;
			sockets_key_for_md.proto = IPPROTO_UDP;
			break;

		default:
			return TC_ACT_OK;
		}
		break;
	}

	event.netns_id =
		skb->cb[0]; // cb[0] initialized by dispatcher.bpf.c to get the netns
	sockets_key_for_md.netns = event.netns_id;
	event.proc.comm[0] = '\0';
	event.proc.parent.comm[0] = '\0';

	/* We always check based on the target ip filter. So in case of egress, our ip filter drops packets 
	going to that IP i.e whose destination is that. In case of ingress, we filter packets coming from that IP
	, so we swap the src and dst for ingress do the check
	and swap it back before the map operations are performed */

	return rand_pkt_drop_map_update(&event, &key, &sockets_key_for_md);
}

SEC("classifier/egress/drop")
int egress_pkt_drop(struct __sk_buff *skb)
{
	if (egress == true)
		return packet_drop(skb);
	else
		return TC_ACT_OK;
}

/* Extremly similar to egress */
SEC("classifier/ingress/drop")
int ingress_pkt_drop(struct __sk_buff *skb)
{
	if (ingress == true)
		return packet_drop(skb);
	else
		return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";