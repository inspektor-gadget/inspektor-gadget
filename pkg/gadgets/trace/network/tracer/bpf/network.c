// SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0
/* Copyright (c) 2023 The Inspektor Gadget authors */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GADGET_TYPE_NETWORKING
#include <gadget/sockets-map.h>

#include "network.h"

// we need this to make sure the compiler doesn't remove our struct
const struct event_t *unusedevent __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

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

	struct event_t event = {};
	__builtin_memset(&event, 0, sizeof(event));
	event.netns = skb->cb[0]; // cb[0] initialized by dispatcher.bpf.c
	event.timestamp = bpf_ktime_get_boot_ns();
	event.pkt_type = skb->pkt_type;
	event.proto = iph.protocol;
	event.port = port;
	event.ip = skb->pkt_type == PACKET_HOST ? iph.saddr : iph.daddr;

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

	bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &event,
			      sizeof(event));

	return 0;
}

char _license[] SEC("license") = "GPL";
