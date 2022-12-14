// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 The Inspektor Gadget authors */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <sys/socket.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <sockets-map.h>

#include "dns-common.h"

#define DNS_OFF (ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr))

// we need this to make sure the compiler doesn't remove our struct
const struct event_t *unusedevent __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
union dnsflags {
	struct {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		__u8 rcode :4;	// response code
		__u8 z :3;	// reserved
		__u8 ra :1;	// recursion available
		__u8 rd :1;	// recursion desired
		__u8 tc :1;	// truncation
		__u8 aa :1;	// authoritive answer
		__u8 opcode :4;	// kind of query
		__u8 qr :1;	// 0=query; 1=response
#elif __BYTE_ORDER == __ORDER_BIG_ENDIAN__
		__u8 qr :1;	// 0=query; 1=response
		__u8 opcode :4;	// kind of query
		__u8 aa :1;	// authoritive answer
		__u8 tc :1;	// truncation
		__u8 rd :1;	// recursion desired
		__u8 ra :1;	// recursion available
		__u8 z :3;	// reserved
		__u8 rcode :4;	// response code
#else
# error "Fix your compiler's __BYTE_ORDER__?!"
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

SEC("socket1")
int ig_trace_dns(struct __sk_buff *skb)
{
	// Skip non-IP packets
	if (load_half(skb, offsetof(struct ethhdr, h_proto)) != ETH_P_IP)
		return 0;

	// Skip non-UDP packets
	if (load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol)) != IPPROTO_UDP)
		return 0;

	union dnsflags flags;
	flags.flags = load_half(skb, DNS_OFF + offsetof(struct dnshdr, flags));

	// Skip DNS packets with more than 1 question
	if (load_half(skb, DNS_OFF + offsetof(struct dnshdr, qdcount)) != 1)
		return 0;

	__u16 ancount = load_half(skb, DNS_OFF + offsetof(struct dnshdr, ancount));
	__u16 nscount = load_half(skb, DNS_OFF + offsetof(struct dnshdr, nscount));
	// Skip DNS queries with answers
	if ((flags.qr == 0) && (ancount + nscount != 0))
		return 0;

	// This loop iterates over the DNS labels to find the total DNS name
	// length.
	unsigned int i;
	unsigned int skip = 0;
	for (i = 0; i < MAX_DNS_NAME ; i++) {
		if (skip != 0) {
			skip--;
		} else {
			int label_len = load_byte(skb, DNS_OFF + sizeof(struct dnshdr) + i);
			if (label_len == 0)
				break;
			// The simple solution "i += label_len" gives verifier
			// errors, so work around with skip.
			skip = label_len;
		}
	}

	__u32 len = i < MAX_DNS_NAME ? i : MAX_DNS_NAME;
	if  (len == 0)
		return 0;

	struct event_t event = {0,};
	event.timestamp = bpf_ktime_get_boot_ns();
	event.id = load_half(skb, DNS_OFF + offsetof(struct dnshdr, id));
	event.af = AF_INET;
	event.daddr_v4 = load_word(skb, ETH_HLEN + offsetof(struct iphdr, daddr));
	event.saddr_v4 = load_word(skb, ETH_HLEN + offsetof(struct iphdr, saddr));
	// load_word converts from network to host endianness. Convert back to
	// network endianness because inet_ntop() requires it.
	event.daddr_v4 = bpf_htonl(event.daddr_v4);
	event.saddr_v4 = bpf_htonl(event.saddr_v4);

	event.qr = flags.qr;

	if (flags.qr == 1) {
		// Response code set only for replies.
		event.rcode = flags.rcode;
	}

	bpf_skb_load_bytes(skb, DNS_OFF + sizeof(struct dnshdr), event.name, len);

	event.pkt_type = skb->pkt_type;

	// Read QTYPE right after the QNAME
	// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
	event.qtype = load_half(skb, DNS_OFF + sizeof(struct dnshdr) + len + 1);

	// Enrich event with process metadata
	struct sockets_value *skb_val = gadget_socket_lookup(skb);
	if (skb_val != NULL) {
		event.mount_ns_id = skb_val->mntns;
		event.pid = skb_val->pid_tgid >> 32;
		event.tid = (__u32)skb_val->pid_tgid;
		__builtin_memcpy(&event.task,  skb_val->task, sizeof(event.task));
	}

	bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	return 0;
}

char _license[] SEC("license") = "GPL";
