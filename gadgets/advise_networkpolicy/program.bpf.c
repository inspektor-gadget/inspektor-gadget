// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 The Inspektor Gadget authors */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <stdbool.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/maps.bpf.h>

#define GADGET_TYPE_NETWORKING
#include <gadget/sockets-map.h>

#define PACKET_HOST 0
#define PACKET_OUTGOING 4

struct event_t {
	gadget_netns_id netns_id;
	gadget_timestamp timestamp_raw;

	struct gadget_process proc;

	struct gadget_l4endpoint_t endpoint;
	__u8 egress;
};

struct empty_t {
	__u8 unused;
};

const struct empty_t zero = {};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct event_t);
	__type(value, struct empty_t);
} packets SEC(".maps");

GADGET_MAPITER(events, packets);

SEC("socket1")
int ig_trace_net(struct __sk_buff *skb)
{
	// Skip multicast, broadcast, forwarding...
	if (skb->pkt_type != PACKET_HOST && skb->pkt_type != PACKET_OUTGOING)
		return 0;

	// Skip frames with non-IP Ethernet protocol.
	struct ethhdr ethh;
	if (bpf_skb_load_bytes(skb, 0, &ethh, sizeof ethh))
		return 0;
	if (bpf_ntohs(ethh.h_proto) != ETH_P_IP)
		return 0;

	int ip_off = ETH_HLEN;
	// Read the IP header.
	struct iphdr iph;
	if (bpf_skb_load_bytes(skb, ip_off, &iph, sizeof iph))
		return 0;

	// An IPv4 header doesn't have a fixed size. The IHL field of a packet
	// represents the size of the IP header in 32-bit words, so we need to
	// multiply this value by 4 to get the header size in bytes.
	__u8 ip_header_len = iph.ihl * 4;
	int l4_off = ip_off + ip_header_len;
	__u16 port;

	if (iph.protocol == IPPROTO_TCP) {
		// Read the TCP header.
		struct tcphdr tcph;
		if (bpf_skb_load_bytes(skb, l4_off, &tcph, sizeof tcph))
			return 0;

		if (!tcph.syn || tcph.ack)
			return 0;

		port = bpf_htons(tcph.dest);
	} else if (iph.protocol == IPPROTO_UDP) {
		// Read the UDP header.
		struct udphdr udph;
		if (bpf_skb_load_bytes(skb, l4_off, &udph, sizeof udph))
			return 0;

		// UDP packets don't have a TCP-SYN to identify the direction.
		// Check usage of dynamic ports instead.
		// https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
		// System Ports: 0-1023
		// User Ports: 1024-49151
		// Dynamic and/or Private Ports: 49152-65535
		// However, Linux uses ephemeral ports: 32768-60999 (/proc/sys/net/ipv4/ip_local_port_range)
		// And /proc/sys/net/ipv4/ip_unprivileged_port_start: 1024
		if (bpf_htons(udph.dest) < 1024)
			port = bpf_htons(udph.dest);
		else
			return 0;
	} else {
		// Skip packets with IP protocol other than TCP/UDP.
		return 0;
	}

	struct event_t event = {};
	__builtin_memset(&event, 0, sizeof(event));
	event.netns_id = skb->cb[0]; // cb[0] initialized by dispatcher.bpf.c
	event.timestamp_raw = bpf_ktime_get_boot_ns();

	if (skb->pkt_type == PACKET_HOST) {
		event.endpoint.addr_raw.v4 = iph.saddr;
	} else {
		event.endpoint.addr_raw.v4 = iph.daddr;
	}
	event.endpoint.proto_raw = iph.protocol;
	event.endpoint.port = port;
	event.endpoint.version = 4;
	event.egress = skb->pkt_type != PACKET_OUTGOING;

	struct sockets_value *skb_val = gadget_socket_lookup(skb);
	gadget_process_populate_from_socket(skb_val, &event.proc);

	bpf_printk("event: %d", event.netns_id);
	bpf_map_update_elem(&packets, &event, &zero, BPF_ANY);

	return 0;
}

char _license[] SEC("license") = "GPL";
