// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 The Inspektor Gadget authors */

// Avoid CO-RE:
// CO-RE relocations: relocate struct#35["iphdr"]: target struct#49626["iphdr"]: target struct#49626["iphdr"]: field "ihl" is a bitfield: not supported 
// 
// #include <vmlinux/vmlinux.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "graph.h"

#include "graphmap.h"

#ifndef ETH_P_IP
#define ETH_P_IP	0x0800
#endif

#ifndef ETH_HLEN
#define ETH_HLEN	14
#endif

#ifndef PACKET_HOST
#define PACKET_HOST		0		/* To us		*/
#endif

#ifdef PACKET_OUTGOING
#define PACKET_OUTGOING		4		/* Outgoing of any type */
#endif

const volatile u64 container_quark = 0;

SEC("socket1")
int bpf_prog1(struct __sk_buff *skb)
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
	u16 port;

	if (iph.protocol == IPPROTO_TCP) {
		// Read the TCP header.
		struct tcphdr tcph;
		if (bpf_skb_load_bytes(skb, l4_off, &tcph, sizeof tcph))
			return 0;

		if (!tcph.syn || tcph.ack)
			return 0;

		port = tcph.dest;
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
			port = udph.dest;
		else
			return 0;
	} else {
		// Skip packets with IP protocol other than TCP/UDP.
		return 0;
	}

	struct graph_key_t key = {};
	key.container_quark	= container_quark;
	key.pkt_type		= skb->pkt_type;
	key.proto		= iph.protocol;
	key.port		= port;
	if (skb->pkt_type == PACKET_HOST) {
		key.ip		= iph.saddr;
	} else {
		key.ip		= iph.daddr;
	}
	u64 zero = 0;

	bpf_map_update_elem(&graphmap, &key, &zero, BPF_ANY);

	return 0;
}

char _license[] SEC("license") = "GPL";
