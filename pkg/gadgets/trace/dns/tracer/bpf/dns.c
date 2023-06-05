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

#define GADGET_TYPE_NETWORKING
#include <sockets-map.h>

#include "dns-common.h"

#define DNS_OFF (ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr))

#define DNS_CLASS_IN 1   // https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4
#define DNS_TYPE_A 1     // https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
#define DNS_TYPE_AAAA 28 // https://www.rfc-editor.org/rfc/rfc3596#section-2.1

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

// DNS resource record
// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3
#pragma pack(2)
struct dnsrr {
	__u16 name; // Two octets when using message compression, see https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
	__u16 type;
	__u16 class;
	__u32 ttl;
	__u16 rdlength;
	// Followed by rdata
};

// The stack is limited, so use a map to build the event
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct event_t);
} tmp_event SEC(".maps");

static __always_inline __u32 dns_name_length(struct __sk_buff *skb)
{
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

	return i < MAX_DNS_NAME ? i : MAX_DNS_NAME;
}

// Save the IPv4 and IPv6 addresses in event->anaddr. Returns the number of saved addresses.
static __always_inline
int load_addresses(struct __sk_buff *skb, int ancount, int anoffset, struct event_t *event)
{
	int rroffset = anoffset;
	int index = 0;
	for (int i = 0; i < ancount && i < MAX_ADDR_ANSWERS; i++) {
		__u16 rrname = load_byte(skb, rroffset + offsetof(struct dnsrr, name));

		// In most cases, the name will be compressed to two octets (indicated by first two bits 0b11).
		// The offset calculations below assume compression, so exit early if the name isn't compressed.
		if ((rrname & 0xf0) != 0xc0)
			return 0;

		// Safe to assume that all answers refer to the same domain name
		// because we verified earlier that there's exactly one question.

		__u16 rrtype = load_half(skb, rroffset + offsetof(struct dnsrr, type));
		__u16 rrclass = load_half(skb, rroffset + offsetof(struct dnsrr, class));
		__u16 rdlength = load_half(skb, rroffset + offsetof(struct dnsrr, rdlength));

		if (rrtype == DNS_TYPE_A && rrclass == DNS_CLASS_IN && rdlength == 4) {
			// A record contains an IPv4 address.
			// Encode this as IPv4-mapped-IPv6 in the BPF event (::ffff:<ipv4>)
			// https://datatracker.ietf.org/doc/html/rfc4291#section-2.5.5.2
			__builtin_memset(&event->anaddr[index][0], 0x0, 10);
			__builtin_memset(&event->anaddr[index][10], 0xff, 2);
			bpf_skb_load_bytes(skb, rroffset + sizeof(struct dnsrr), &event->anaddr[index][12], rdlength);
			index++;
		} else if (rrtype == DNS_TYPE_AAAA && rrclass == DNS_CLASS_IN && rdlength == 16) {
			// AAAA record contains an IPv6 address.
			bpf_skb_load_bytes(skb, rroffset + sizeof(struct dnsrr), &event->anaddr[index][0], rdlength);
			index++;
		}
		rroffset += sizeof(struct dnsrr) + rdlength;
	}
	return index;
}

static __always_inline int
output_dns_event(struct __sk_buff *skb, union dnsflags flags, __u32 name_len, __u16 ancount)
{
	__u32 zero = 0;
	struct event_t *event = bpf_map_lookup_elem(&tmp_event, &zero);
	if (!event)
		return 0;

	__builtin_memset(event, 0, sizeof(*event));

	event->timestamp = bpf_ktime_get_boot_ns();
	event->id = load_half(skb, DNS_OFF + offsetof(struct dnshdr, id));
	event->af = AF_INET;
	event->daddr_v4 = load_word(skb, ETH_HLEN + offsetof(struct iphdr, daddr));
	event->saddr_v4 = load_word(skb, ETH_HLEN + offsetof(struct iphdr, saddr));
	// load_word converts from network to host endianness. Convert back to
	// network endianness because inet_ntop() requires it.
	event->daddr_v4 = bpf_htonl(event->daddr_v4);
	event->saddr_v4 = bpf_htonl(event->saddr_v4);

	event->qr = flags.qr;

	if (flags.qr == 1) {
		// Response code set only for replies.
		event->rcode = flags.rcode;
	}

	bpf_skb_load_bytes(skb, DNS_OFF + sizeof(struct dnshdr), event->name, name_len);

	event->pkt_type = skb->pkt_type;

	// Read QTYPE right after the QNAME (name_len + the zero length octet)
	// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
	event->qtype = load_half(skb, DNS_OFF + sizeof(struct dnshdr) + name_len + 1);

	// Enrich event with process metadata
	struct sockets_value *skb_val = gadget_socket_lookup(skb);
	if (skb_val != NULL) {
		event->mount_ns_id = skb_val->mntns;
		event->pid = skb_val->pid_tgid >> 32;
		event->tid = (__u32)skb_val->pid_tgid;
		__builtin_memcpy(&event->task,  skb_val->task, sizeof(event->task));
		event->uid = (__u32) skb_val->uid_gid;
		event->gid = (__u32) (skb_val->uid_gid >> 32);
	}

	event->ancount = ancount;

	// DNS answers start immediately after qname (name_len octets)
	// + the zero length octet + qtype (2 octets) + qclass (2 octets).
	int anoffset = DNS_OFF + sizeof(struct dnshdr) + name_len + 5;
	int anaddrcount = load_addresses(skb, ancount, anoffset, event);
	event->anaddrcount = anaddrcount;

	// size of full structure - addresses + only used addresses
	unsigned long long size = sizeof(*event) - MAX_ADDR_ANSWERS*16 + anaddrcount*16;
	bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, event, size);

	return 0;
}

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

	__u32 name_len = dns_name_length(skb);
	if (name_len == 0)
		return 0;

	return output_dns_event(skb, flags, name_len, ancount);
}

char _license[] SEC("license") = "GPL";
