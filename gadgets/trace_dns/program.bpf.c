// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 The Inspektor Gadget authors */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GADGET_TYPE_NETWORKING

#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/sockets-map.h>
#include <gadget/filter.h>

// Don't include <gadget/filesystem.h> in networking gadgets
#define GADGET_PATH_MAX 512

unsigned long long load_byte(const void *skb,
			     unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(const void *skb,
			     unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(const void *skb,
			     unsigned long long off) asm("llvm.bpf.load.word");

#ifndef NEXTHDR_HOP
#define NEXTHDR_HOP 0 /* Hop-by-hop option header. */
#define NEXTHDR_TCP 6 /* TCP segment. */
#define NEXTHDR_UDP 17 /* UDP message. */
#define NEXTHDR_ROUTING 43 /* Routing header. */
#define NEXTHDR_FRAGMENT 44 /* Fragmentation/reassembly header. */
#define NEXTHDR_AUTH 51 /* Authentication header. */
#define NEXTHDR_NONE 59 /* No next header */
#define NEXTHDR_DEST 60 /* Destination options header. */
#endif

#define DNS_QR_QUERY 0
#define DNS_QR_RESP 1

#define MAX_PORTS 16
const volatile __u16 ports[MAX_PORTS] = { 53, 5353 };
const volatile __u16 ports_len = 2;
const volatile bool paths = false;
GADGET_PARAM(paths);

static __always_inline bool is_dns_port(__u16 port)
{
	for (int i = 0; i < ports_len; i++) {
		if (ports[i] == port)
			return true;
	}
	return false;
}

enum pkt_type_t : __u8 {
	HOST,
	BROADCAST,
	MULTICAST,
	OTHERHOST,
	OUTGOING,
	LOOPBACK,
	USER,
	KERNEL,
};

// TODO: what's a reasonable value for this?
// Or can we remove this altogether?
#define MAX_PACKET (1024 * 9) // 9KB

struct event_t {
	gadget_timestamp timestamp_raw;
	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;
	struct gadget_l3endpoint_t nameserver;
	gadget_netns_id netns_id;
	struct gadget_process proc;
	char cwd[GADGET_PATH_MAX];
	char exepath[GADGET_PATH_MAX];

	enum pkt_type_t pkt_type_raw;
	gadget_duration
		latency_ns_raw; // Set only if the packet is a response and pkt_type is 0 (Host).

	__u16 dns_off; // DNS offset in the packet
	__u32 data_len;

	// Only on this structure
	__u8 data[MAX_PACKET];
};

// TODO: We need this header structure as the packet itself is appended by
// bpf_perf_event_output(). Hence the event we send over the perf ring buffer is
// only the header without the packet. We can use the full structure above as
// it exceeds the stack limit of 512 bytes in bpf.
// TODO: We'll need to find a clearer way to implement this
struct event_header_t {
	gadget_timestamp timestamp_raw;
	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;
	struct gadget_l3endpoint_t nameserver;
	gadget_netns_id netns_id;
	struct gadget_process proc;
	char cwd[GADGET_PATH_MAX];
	char exepath[GADGET_PATH_MAX];

	enum pkt_type_t pkt_type_raw;
	gadget_duration
		latency_ns_raw; // Set only if the packet is a response and pkt_type is 0 (Host).

	__u16 dns_off; // DNS offset in the packet
	__u32 data_len;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

GADGET_TRACER(dns, events, event_t);

// Cannot use gadget_reserve_buf() because this does not support
// bpf_perf_event_output with packet appended
static const struct gadget_process empty_proc = {};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct event_t));
} tmp_events SEC(".maps");

// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
union dnsflags {
	struct {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		__u8 rcode : 4; // response code
		__u8 z : 3; // reserved
		__u8 ra : 1; // recursion available
		__u8 rd : 1; // recursion desired
		__u8 tc : 1; // truncation
		__u8 aa : 1; // authoritative answer
		__u8 opcode : 4; // kind of query
		__u8 qr : 1; // 0=query; 1=response
#elif __BYTE_ORDER == __ORDER_BIG_ENDIAN__
		__u8 qr : 1; // 0=query; 1=response
		__u8 opcode : 4; // kind of query
		__u8 aa : 1; // authoritative answer
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
	__u16 pad[3]; // this is needed, otherwise the verifier claims an invalid read from stack
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
	struct event_header_t *event;
	int zero = 0;
	__u16 sport, dport, l4_off, dns_off, h_proto, id;
	__u8 proto;
	int i;

	// Do a first pass only to extract the port and drop the packet if it's not DNS
	h_proto = load_half(skb, offsetof(struct ethhdr, h_proto));
	switch (h_proto) {
	case ETH_P_IP:
		proto = load_byte(skb,
				  ETH_HLEN + offsetof(struct iphdr, protocol));
		// An IPv4 header doesn't have a fixed size. The IHL field of a packet
		// represents the size of the IP header in 32-bit words, so we need to
		// multiply this value by 4 to get the header size in bytes.
		__u8 ihl_byte = load_byte(skb, ETH_HLEN);
		struct iphdr *iph = (struct iphdr *)&ihl_byte;
		__u8 ip_header_len = iph->ihl * 4;
		l4_off = ETH_HLEN + ip_header_len;
		break;

	case ETH_P_IPV6:
		proto = load_byte(skb,
				  ETH_HLEN + offsetof(struct ipv6hdr, nexthdr));
		l4_off = ETH_HLEN + sizeof(struct ipv6hdr);

// Parse IPv6 extension headers
// Up to 6 extension headers can be chained. See ipv6_ext_hdr().
#pragma unroll
		for (i = 0; i < 6; i++) {
			__u8 nextproto;

			// TCP or UDP found
			if (proto == NEXTHDR_TCP || proto == NEXTHDR_UDP)
				break;

			nextproto = load_byte(skb, l4_off);

			// Unfortunately, each extension header has a different way to calculate the header length.
			// Support the ones defined in ipv6_ext_hdr(). See ipv6_skip_exthdr().
			switch (proto) {
			case NEXTHDR_FRAGMENT:
				// No hdrlen in the fragment header
				l4_off += 8;
				break;
			case NEXTHDR_AUTH:
				// See ipv6_authlen()
				l4_off += 4 * (load_byte(skb, l4_off + 1) + 2);
				break;
			case NEXTHDR_HOP:
			case NEXTHDR_ROUTING:
			case NEXTHDR_DEST:
				// See ipv6_optlen()
				l4_off += 8 * (load_byte(skb, l4_off + 1) + 1);
				break;
			case NEXTHDR_NONE:
				// Nothing more in the packet. Not even TCP or UDP.
				return 0;
			default:
				// Unknown header
				return 0;
			}
			proto = nextproto;
		}
		break;

	default:
		return 0;
	}

	// Since we have the same offset for source and destination ports for both TCP and UDP,
	// we can use the same code to extract them.
	// - offsetof(struct udphdr, source) == offsetof(struct tcphdr, source)
	// - offsetof(struct udphdr, dest) == offsetof(struct tcphdr, dest)
	switch (proto) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
		sport = load_half(skb,
				  l4_off + offsetof(struct udphdr, source));
		dport = load_half(skb, l4_off + offsetof(struct udphdr, dest));
		break;
	default:
		return 0;
	}

	if (!is_dns_port(sport) && !is_dns_port(dport))
		return 0;

	// Calculate the DNS offset in the packet
	struct tcphdr tcph;
	switch (proto) {
	case IPPROTO_UDP:
		dns_off = l4_off + sizeof(struct udphdr);
		break;
	case IPPROTO_TCP:
		// This is best effort, since we don't reassemble TCP segments.
		if (bpf_skb_load_bytes(skb, l4_off, &tcph, sizeof tcph))
			return 0;

		// The data offset field in the header is specified in 32-bit words. We
		// have to multiply this value by 4 to get the TCP header length in bytes.
		__u8 tcp_header_len = tcph.doff * 4;

		// Skip if we don't have any data to avoid handling control segments
		dns_off = l4_off + tcp_header_len;
		if (skb->len <= dns_off)
			return 0;

		// DNS is after the TCP header and the 2 bytes of the length of the DNS packet
		dns_off += 2;
		break;
	default:
		return 0;
	}

	event = bpf_map_lookup_elem(&tmp_events, &zero);
	if (!event)
		return 0; // it never happens

	// As an optimization, only clear the fields that can be skipped below.
	event->latency_ns_raw = 0;
	event->proc = empty_proc;
	if (paths) {
		event->cwd[0] = '\0';
		event->exepath[0] = '\0';
	}

	event->timestamp_raw = bpf_ktime_get_boot_ns();
	event->netns_id = skb->cb[0]; // cb[0] initialized by dispatcher.bpf.c
	event->data_len = skb->len;
	event->dns_off = dns_off;
	event->pkt_type_raw = skb->pkt_type;
	event->src.proto_raw = event->dst.proto_raw = proto;
	event->src.port = sport;
	event->dst.port = dport;

	// The packet is DNS: Do a second pass to extract all the information we need
	switch (h_proto) {
	case ETH_P_IP:
		event->src.version = event->dst.version = 4;
		event->dst.addr_raw.v4 = load_word(
			skb, ETH_HLEN + offsetof(struct iphdr, daddr));
		event->src.addr_raw.v4 = load_word(
			skb, ETH_HLEN + offsetof(struct iphdr, saddr));
		// load_word converts from network to host endianness. Convert back to
		// network endianness because Inspektor Gadget needs this format for IP addresses.
		event->src.addr_raw.v4 = bpf_htonl(event->src.addr_raw.v4);
		event->dst.addr_raw.v4 = bpf_htonl(event->dst.addr_raw.v4);
		break;
	case ETH_P_IPV6:
		event->src.version = event->dst.version = 6;
		if (bpf_skb_load_bytes(
			    skb, ETH_HLEN + offsetof(struct ipv6hdr, saddr),
			    &event->src.addr_raw.v6,
			    sizeof(event->src.addr_raw.v6)))
			return 0;
		if (bpf_skb_load_bytes(
			    skb, ETH_HLEN + offsetof(struct ipv6hdr, daddr),
			    &event->dst.addr_raw.v6,
			    sizeof(event->dst.addr_raw.v6)))
			return 0;
		break;
	}

	struct sockets_value *skb_val = gadget_socket_lookup(skb);
	if (gadget_should_discard_data_by_skb(skb_val))
		return 0;

	// Enrich event with process metadata
	gadget_process_populate_from_socket(skb_val, &event->proc);

	if (paths && skb_val != NULL) {
		if (bpf_core_enum_value_exists(
			    enum bpf_func_id, BPF_FUNC_probe_read_kernel_str)) {
			bpf_probe_read_kernel_str(
				&event->cwd, sizeof(event->cwd), skb_val->cwd);
			bpf_probe_read_kernel_str(&event->exepath,
						  sizeof(event->exepath),
						  skb_val->exepath);
		} else {
			if (sizeof(skb_val->cwd) <= sizeof(event->cwd)) {
				int cwd_len = sizeof(skb_val->cwd);
				if (bpf_skb_load_bytes(
					    skb, (unsigned long)skb_val->cwd,
					    event->cwd, cwd_len) < 0) {
					return 0;
				}
			}

			if (sizeof(skb_val->exepath) <=
			    sizeof(event->exepath)) {
				int exepath_len = sizeof(skb_val->exepath);
				if (bpf_skb_load_bytes(
					    skb,
					    (unsigned long)skb_val->exepath,
					    event->exepath, exepath_len) < 0) {
					return 0;
				}
			}
		}
	}

	// Handle nameserver
	union dnsflags flags;
	flags.flags = load_half(skb, dns_off + offsetof(struct dnshdr, flags));
	__u8 qr = flags.qr;
	if (qr == DNS_QR_QUERY) {
		event->nameserver.version = event->dst.version;
		event->nameserver.addr_raw = event->dst.addr_raw;
	} else if (qr == DNS_QR_RESP) {
		event->nameserver.version = event->src.version;
		event->nameserver.addr_raw = event->src.addr_raw;
	} else {
		// Unknown QR value
		return 0;
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
	if (skb_val != NULL && event->timestamp_raw > 0) {
		id = load_half(skb, dns_off + offsetof(struct dnshdr, id));

		struct query_key_t query_key = {
			.pid_tgid = skb_val->pid_tgid,
			.id = id,
		};
		if (qr == DNS_QR_QUERY && event->pkt_type_raw == OUTGOING) {
			bpf_map_update_elem(&query_map, &query_key,
					    &event->timestamp_raw, BPF_NOEXIST);
		} else if (flags.qr == DNS_QR_RESP &&
			   event->pkt_type_raw == HOST) {
			__u64 *query_ts =
				bpf_map_lookup_elem(&query_map, &query_key);
			if (query_ts != NULL) {
				// query ts should always be less than the event ts, but check anyway to be safe.
				if (*query_ts < event->timestamp_raw) {
					event->latency_ns_raw =
						event->timestamp_raw -
						*query_ts;
				}
				bpf_map_delete_elem(&query_map, &query_key);
			}
		}
	}

	__u64 skb_len = skb->len;
	if (skb_len > MAX_PACKET)
		skb_len = MAX_PACKET;
	bpf_perf_event_output(skb, &events, skb_len << 32 | BPF_F_CURRENT_CPU,
			      event, sizeof(*event));

	return 0;
}

char _license[] SEC("license") = "GPL";
