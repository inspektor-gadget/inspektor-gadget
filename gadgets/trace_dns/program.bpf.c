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

#include <gadget/macros.h>
#include <gadget/types.h>

#define GADGET_TYPE_NETWORKING
#include <gadget/sockets-map.h>

// Max DNS name length: 255
// https://datatracker.ietf.org/doc/html/rfc1034#section-3.1
#define MAX_DNS_NAME 255

#define TASK_COMM_LEN 16

// Maximum number of A or AAAA answers to include in the DNS event.
// The DNS reply could have more answers than this, but the additional
// answers won't be sent to userspace.
#define MAX_ADDR_ANSWERS 1

struct event_t {
	__u64 timestamp;

	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;

	mnt_ns_id_t mntns_id;
	__u32 netns;
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 gid;
	__u8 task[TASK_COMM_LEN];

	__u16 id;
	unsigned short qtype;

	// qr says if the dns message is a query (0), or a response (1)
	unsigned char qr;
	unsigned char pkt_type;
	unsigned char rcode;

	__u64 latency_ns; // Set only if qr is 1 (response) and pkt_type is 0 (Host).

	__u8 name[MAX_DNS_NAME];

	__u16 ancount;
	__u16 anaddrcount;
	__u8 anaddr[MAX_ADDR_ANSWERS]
		   [16]; // Either IPv4-mapped-IPv6 (A record) or IPv6 (AAAA record) addresses.
};

#define DNS_OFF (ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr))

#define DNS_CLASS_IN \
	1 // https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4
#define DNS_TYPE_A \
	1 // https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
#define DNS_TYPE_AAAA 28 // https://www.rfc-editor.org/rfc/rfc3596#section-2.1

#ifndef PACKET_HOST
#define PACKET_HOST 0x0
#endif

#ifndef PACKET_OUTGOING
#define PACKET_OUTGOING 0x4
#endif

#define DNS_QR_QUERY 0
#define DNS_QR_RESP 1

// we need this to make sure the compiler doesn't remove our struct
const struct event_t *unusedevent __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__type(value, struct event_t);
} events SEC(".maps");

GADGET_TRACE_MAP(events);

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

static __always_inline __u32 dns_name_length(struct __sk_buff *skb)
{
	// This loop iterates over the DNS labels to find the total DNS name
	// length.
	unsigned int i;
	unsigned int skip = 0;
	for (i = 0; i < MAX_DNS_NAME; i++) {
		if (skip != 0) {
			skip--;
		} else {
			int label_len = load_byte(
				skb, DNS_OFF + sizeof(struct dnshdr) + i);
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
static __always_inline int load_addresses(struct __sk_buff *skb, int ancount,
					  int anoffset, struct event_t *event)
{
	int rroffset = anoffset;
	int index = 0;
	for (int i = 0; i < ancount && i < MAX_ADDR_ANSWERS; i++) {
		__u16 rrname =
			load_byte(skb, rroffset + offsetof(struct dnsrr, name));

		// In most cases, the name will be compressed to two octets (indicated by first two bits 0b11).
		// The offset calculations below assume compression, so exit early if the name isn't compressed.
		if ((rrname & 0xf0) != 0xc0)
			return 0;

		// Safe to assume that all answers refer to the same domain name
		// because we verified earlier that there's exactly one question.

		__u16 rrtype =
			load_half(skb, rroffset + offsetof(struct dnsrr, type));
		__u16 rrclass = load_half(skb, rroffset + offsetof(struct dnsrr,
								   class));
		__u16 rdlength = load_half(
			skb, rroffset + offsetof(struct dnsrr, rdlength));

		if (rrtype == DNS_TYPE_A && rrclass == DNS_CLASS_IN &&
		    rdlength == 4) {
			// A record contains an IPv4 address.
			// Encode this as IPv4-mapped-IPv6 in the BPF event (::ffff:<ipv4>)
			// https://datatracker.ietf.org/doc/html/rfc4291#section-2.5.5.2
			__builtin_memset(&event->anaddr[index][0], 0x0, 10);
			__builtin_memset(&event->anaddr[index][10], 0xff, 2);
			bpf_skb_load_bytes(skb, rroffset + sizeof(struct dnsrr),
					   &event->anaddr[index][12], rdlength);
			index++;
		} else if (rrtype == DNS_TYPE_AAAA && rrclass == DNS_CLASS_IN &&
			   rdlength == 16) {
			// AAAA record contains an IPv6 address.
			bpf_skb_load_bytes(skb, rroffset + sizeof(struct dnsrr),
					   &event->anaddr[index][0], rdlength);
			index++;
		}
		rroffset += sizeof(struct dnsrr) + rdlength;
	}
	return index;
}

static __always_inline int output_dns_event(struct __sk_buff *skb,
					    union dnsflags flags,
					    __u32 name_len, __u16 ancount)
{
	__u32 zero = 0;
	struct event_t *event = bpf_map_lookup_elem(&tmp_event, &zero);
	if (!event)
		return 0;

	__builtin_memset(event, 0, sizeof(*event));

	event->netns = skb->cb[0]; // cb[0] initialized by dispatcher.bpf.c
	event->timestamp = bpf_ktime_get_boot_ns();
	event->id = load_half(skb, DNS_OFF + offsetof(struct dnshdr, id));

	event->src.l3.version = event->dst.l3.version = 4;
	event->dst.l3.addr.v4 =
		load_word(skb, ETH_HLEN + offsetof(struct iphdr, daddr));
	event->src.l3.addr.v4 =
		load_word(skb, ETH_HLEN + offsetof(struct iphdr, saddr));
	// load_word converts from network to host endianness. Convert back to
	// network endianness as required by gadget_l4endpoint_t.
	event->dst.l3.addr.v4 = bpf_htonl(event->dst.l3.addr.v4);
	event->src.l3.addr.v4 = bpf_htonl(event->src.l3.addr.v4);

	// Check network protocol.
	// This only works with IPv4.
	// For IPv6, gadget_socket_lookup() in pkg/gadgets/internal/socketenricher/bpf/sockets-map.h
	// provides an example how to parse ip/ports on IPv6.
	event->src.proto = event->dst.proto =
		load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
	if (event->src.proto == IPPROTO_TCP) {
		event->src.port =
			load_half(skb, ETH_HLEN + sizeof(struct iphdr) +
					       offsetof(struct tcphdr, source));
		event->dst.port =
			load_half(skb, ETH_HLEN + sizeof(struct iphdr) +
					       offsetof(struct tcphdr, dest));
	} else if (event->src.proto == IPPROTO_UDP) {
		event->src.port =
			load_half(skb, ETH_HLEN + sizeof(struct iphdr) +
					       offsetof(struct udphdr, source));
		event->dst.port =
			load_half(skb, ETH_HLEN + sizeof(struct iphdr) +
					       offsetof(struct udphdr, dest));
	}

	event->qr = flags.qr;

	if (flags.qr == 1) {
		// Response code set only for replies.
		event->rcode = flags.rcode;
	}

	bpf_skb_load_bytes(skb, DNS_OFF + sizeof(struct dnshdr), event->name,
			   name_len);

	event->pkt_type = skb->pkt_type;

	// Read QTYPE right after the QNAME (name_len + the zero length octet)
	// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
	event->qtype =
		load_half(skb, DNS_OFF + sizeof(struct dnshdr) + name_len + 1);

	// Enrich event with process metadata
	struct sockets_value *skb_val = gadget_socket_lookup(skb);
	if (skb_val != NULL) {
		event->mntns_id = skb_val->mntns;
		event->pid = skb_val->pid_tgid >> 32;
		event->tid = (__u32)skb_val->pid_tgid;
		__builtin_memcpy(&event->task, skb_val->task,
				 sizeof(event->task));
		event->uid = (__u32)skb_val->uid_gid;
		event->gid = (__u32)(skb_val->uid_gid >> 32);
	}

	event->ancount = ancount;

	// DNS answers start immediately after qname (name_len octets)
	// + the zero length octet + qtype (2 octets) + qclass (2 octets).
	int anoffset = DNS_OFF + sizeof(struct dnshdr) + name_len + 5;
	int anaddrcount = load_addresses(skb, ancount, anoffset, event);
	event->anaddrcount = anaddrcount;

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
	if (skb_val != NULL && event->timestamp > 0) {
		struct query_key_t query_key = {
			.pid_tgid = skb_val->pid_tgid,
			.id = event->id,
		};
		if (event->qr == DNS_QR_QUERY &&
		    event->pkt_type == PACKET_OUTGOING) {
			bpf_map_update_elem(&query_map, &query_key,
					    &event->timestamp, BPF_NOEXIST);
		} else if (event->qr == DNS_QR_RESP &&
			   event->pkt_type == PACKET_HOST) {
			__u64 *query_ts =
				bpf_map_lookup_elem(&query_map, &query_key);
			if (query_ts != NULL) {
				// query ts should always be less than the event ts, but check anyway to be safe.
				if (*query_ts < event->timestamp) {
					event->latency_ns =
						event->timestamp - *query_ts;
				}
				bpf_map_delete_elem(&query_map, &query_key);
			}
		}
	}

	// size of full structure - addresses + only used addresses
	unsigned long long size =
		sizeof(*event); // - MAX_ADDR_ANSWERS * 16 + anaddrcount * 16;
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
	if (load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol)) !=
	    IPPROTO_UDP)
		return 0;

	union dnsflags flags;
	flags.flags = load_half(skb, DNS_OFF + offsetof(struct dnshdr, flags));

	// Skip DNS packets with more than 1 question
	if (load_half(skb, DNS_OFF + offsetof(struct dnshdr, qdcount)) != 1)
		return 0;

	__u16 ancount =
		load_half(skb, DNS_OFF + offsetof(struct dnshdr, ancount));
	__u16 nscount =
		load_half(skb, DNS_OFF + offsetof(struct dnshdr, nscount));

	// Skip DNS queries with answers
	if (flags.qr == 0 && ancount + nscount != 0)
		return 0;

	__u32 name_len = dns_name_length(skb);
	if (name_len == 0)
		return 0;

	return output_dns_event(skb, flags, name_len, ancount);
}

char _license[] SEC("license") = "GPL";
