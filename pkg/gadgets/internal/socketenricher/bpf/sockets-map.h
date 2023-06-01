/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0 */

#ifndef SOCKETS_MAP_H
#define SOCKETS_MAP_H

#ifdef GADGET_TYPE_NETWORKING

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#endif

#ifndef PACKET_HOST
#define PACKET_HOST		0
#endif

#ifndef PACKET_OUTGOING
#define PACKET_OUTGOING		4
#endif

#ifndef ETH_HLEN
#define ETH_HLEN	14
#endif

#ifndef ETH_P_IP
#define ETH_P_IP        0x0800          /* Internet Protocol packet     */
#endif

#ifndef AF_INET
#define AF_INET		2	/* Internet IP Protocol 	*/
#endif

#ifndef AF_INET6
#define AF_INET6 10      /* IP version 6                 */
#endif

// See include/net/ipv6.h
#ifndef NEXTHDR_NONE
#define NEXTHDR_HOP             0       /* Hop-by-hop option header. */
#define NEXTHDR_TCP             6       /* TCP segment. */
#define NEXTHDR_UDP             17      /* UDP message. */
#define NEXTHDR_ROUTING         43      /* Routing header. */
#define NEXTHDR_FRAGMENT        44      /* Fragmentation/reassembly header. */
#define NEXTHDR_AUTH            51      /* Authentication header. */
#define NEXTHDR_NONE            59      /* No next header */
#define NEXTHDR_DEST            60      /* Destination options header. */
#endif

#ifdef GADGET_TYPE_NETWORKING

const volatile __u32 current_netns = 0;

unsigned long long load_byte(const void *skb,
			     unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(const void *skb,
			     unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(const void *skb,
			     unsigned long long off) asm("llvm.bpf.load.word");

#endif


struct sockets_key {
	__u32 netns;
	__u16 family;

	// proto is IPPROTO_TCP(6) or IPPROTO_UDP(17)
	__u16 proto;
	__u16 port;
};

#define TASK_COMM_LEN	16
struct sockets_value {
	__u64 mntns;
	__u64 pid_tgid;
	char task[TASK_COMM_LEN];
	__u64 sock;
	__u64 deletion_timestamp;
};

#define MAX_SOCKETS	16384
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SOCKETS);
	__type(key, struct sockets_key);
	__type(value, struct sockets_value);
} sockets SEC(".maps");

#ifdef GADGET_TYPE_NETWORKING
static __always_inline struct sockets_value *
gadget_socket_lookup(const struct __sk_buff *skb)
{
	struct sockets_key key = {0,};
	int l4_off;
	__u16 h_proto;
	int i;

	key.netns = current_netns;
	h_proto = load_half(skb, offsetof(struct ethhdr, h_proto));
	switch (h_proto) {
	case ETH_P_IP:
		key.family = AF_INET;
		key.proto = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));

		// An IPv4 header doesn't have a fixed size. The IHL field of a packet
		// represents the size of the IP header in 32-bit words, so we need to
		// multiply this value by 4 to get the header size in bytes.
		__u8 ihl_byte = load_byte(skb, ETH_HLEN);
		struct iphdr *iph = (struct iphdr *)&ihl_byte;
		__u8 ip_header_len = iph->ihl * 4;
		l4_off = ETH_HLEN + ip_header_len;
		break;

	case ETH_P_IPV6:
		key.family = AF_INET6;
		key.proto = load_byte(skb, ETH_HLEN + offsetof(struct ipv6hdr, nexthdr));
		l4_off = ETH_HLEN + sizeof(struct ipv6hdr);

		// Parse IPv6 extension headers
		// Up to 6 extension headers can be chained. See ipv6_ext_hdr().
		#pragma unroll
		for (i = 0; i < 6; i++) {
			__u16 nextproto;

			// TCP or UDP found
			if (key.proto == NEXTHDR_TCP || key.proto == NEXTHDR_UDP)
				break;

			nextproto = load_byte(skb, l4_off);

			// Unfortunately, each extension header has a different way to calculate the header length.
			// Support the ones defined in ipv6_ext_hdr(). See ipv6_skip_exthdr().
			switch (key.proto) {
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
			key.proto = nextproto;
		}
		break;

	default:
		return 0;
	}

	switch (key.proto) {
	case IPPROTO_TCP:
		if (skb->pkt_type == PACKET_HOST)
			key.port = load_half(skb, l4_off + offsetof(struct tcphdr, dest));
		else
			key.port = load_half(skb, l4_off + offsetof(struct tcphdr, source));
		break;
	case IPPROTO_UDP:
		if (skb->pkt_type == PACKET_HOST)
			key.port = load_half(skb, l4_off + offsetof(struct udphdr, dest));
		else
			key.port = load_half(skb, l4_off + offsetof(struct udphdr, source));
		break;
	default:
		return 0;
	}

	return bpf_map_lookup_elem(&sockets, &key);
}
#endif

#ifdef GADGET_TYPE_TRACING
static __always_inline struct sockets_value *
gadget_socket_lookup(const struct sock *sk, __u32 netns)
{
	struct sockets_key key = {0,};
	key.netns = netns;
	key.family = BPF_CORE_READ(sk, __sk_common.skc_family);
	key.proto = BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol);
	if (key.proto != IPPROTO_TCP && key.proto != IPPROTO_UDP)
		return 0;

	BPF_CORE_READ_INTO(&key.port, sk, __sk_common.skc_dport);
	struct inet_sock *sockp = (struct inet_sock *)sk;
	BPF_CORE_READ_INTO(&key.port, sockp, inet_sport);
	// inet_sock.inet_sport is in network byte order
	key.port = bpf_ntohs(key.port);

	return bpf_map_lookup_elem(&sockets, &key);
}
#endif

#endif
