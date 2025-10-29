/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0 */

#ifndef SOCKETS_MAP_H
#define SOCKETS_MAP_H

// The include <bpf/bpf_helpers.h> below requires to include either
// <linux/types.h> or <vmlinux.h> before. We can't include both because they
// are incompatible. Let the gadget choose which one to include.
#if !defined(__VMLINUX_H__) && !defined(_LINUX_TYPES_H)
#error "Include <linux/types.h> or <vmlinux.h> before including this file."
#endif

// Necessary for the SEC() definition
#include <bpf/bpf_helpers.h>
#include <gadget/types.h>

// This file is shared between the networking and tracing programs.
// Therefore, avoid includes that are specific to one of these types of programs.
// For example, don't include <linux/ip.h> nor <vmlinux.h> here.
// Redefine the constants we need but namespaced (GADGET_SE_) so we don't pollute gadgets.

#define GADGET_SE_PACKET_HOST 0
#define GADGET_SE_ETH_HLEN 14
#define GADGET_SE_ETH_P_IP 0x0800 /* Internet Protocol packet     */
#define GADGET_SE_ETH_P_IPV6 0x86DD /* IPv6 over bluebook           */
#define GADGET_SE_AF_INET 2 /* Internet IP Protocol 	*/
#define GADGET_SE_AF_INET6 10 /* IP version 6                 */

#define GADGET_SE_IPV6_HLEN 40
#define GADGET_SE_IPV6_NEXTHDR_OFFSET 6 // offsetof(struct ipv6hdr, nexthdr)

#define GADGET_SE_TCPHDR_DEST_OFFSET 2 // offsetof(struct tcphdr, dest);
#define GADGET_SE_TCPHDR_SOURCE_OFFSET 0 // offsetof(struct tcphdr, source);
#define GADGET_SE_UDPHDR_DEST_OFFSET 2 // offsetof(struct udphdr, dest);
#define GADGET_SE_UDPHDR_SOURCE_OFFSET 0 // offsetof(struct udphdr, source);

#define GADGET_SE_NEXTHDR_HOP 0 /* Hop-by-hop option header. */
#define GADGET_SE_NEXTHDR_TCP 6 /* TCP segment. */
#define GADGET_SE_NEXTHDR_UDP 17 /* UDP message. */
#define GADGET_SE_NEXTHDR_ROUTING 43 /* Routing header. */
#define GADGET_SE_NEXTHDR_FRAGMENT 44 /* Fragmentation/reassembly header. */
#define GADGET_SE_NEXTHDR_AUTH 51 /* Authentication header. */
#define GADGET_SE_NEXTHDR_NONE 59 /* No next header */
#define GADGET_SE_NEXTHDR_DEST 60 /* Destination options header. */

struct gadget_socket_key {
	__u32 netns;
	__u16 family;

	// proto is IPPROTO_TCP(6) or IPPROTO_UDP(17)
	__u8 proto;
	__u16 port;
};

#define GADGET_MAX_SOCKETS 16384
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, GADGET_MAX_SOCKETS);
	__type(key, struct gadget_socket_key);
	__type(value, struct gadget_socket_value);
} gadget_sockets SEC(".maps");

#ifdef GADGET_TYPE_NETWORKING
// Helper to lookup a socket based on the skb information and the packet direction.
// This is useful for TC programs since we can't rely on skb->pkt_type to determine
// the packet direction.
static __always_inline struct gadget_socket_value *
gadget_socket_lookup_with_direction(const struct __sk_buff *skb,
				    __u8 is_ingress)
{
	struct gadget_socket_value *ret;
	struct gadget_socket_key key = {
		0,
	};
	int l4_off;
	__u16 h_proto;
	int i;
	long err;

	key.netns = skb->cb[0]; // cb[0] initialized by dispatcher.bpf.c
	err = bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto),
				 &h_proto, sizeof(h_proto));
	if (err < 0)
		return 0;

	switch (h_proto) {
	case bpf_htons(GADGET_SE_ETH_P_IP):
		key.family = GADGET_SE_AF_INET;
		err = bpf_skb_load_bytes(
			skb,
			GADGET_SE_ETH_HLEN + offsetof(struct iphdr, protocol),
			&key.proto, sizeof(key.proto));
		if (err < 0)
			return 0;

		// An IPv4 header doesn't have a fixed size. The IHL field of a packet
		// represents the size of the IP header in 32-bit words, so we need to
		// multiply this value by 4 to get the header size in bytes.
		__u8 ihl_byte;
		err = bpf_skb_load_bytes(skb, GADGET_SE_ETH_HLEN, &ihl_byte,
					 sizeof(ihl_byte));
		if (err < 0)
			return 0;
		struct iphdr *iph = (struct iphdr *)&ihl_byte;
		__u8 ip_header_len = iph->ihl * 4;
		l4_off = GADGET_SE_ETH_HLEN + ip_header_len;
		break;

	case bpf_htons(GADGET_SE_ETH_P_IPV6):
		key.family = GADGET_SE_AF_INET6;
		err = bpf_skb_load_bytes(
			skb, GADGET_SE_ETH_HLEN + GADGET_SE_IPV6_NEXTHDR_OFFSET,
			&key.proto, sizeof(key.proto));
		if (err < 0)
			return 0;
		l4_off = GADGET_SE_ETH_HLEN + GADGET_SE_IPV6_HLEN;

// Parse IPv6 extension headers
// Up to 6 extension headers can be chained. See ipv6_ext_hdr().
#pragma unroll
		for (i = 0; i < 6; i++) {
			__u8 nextproto;
			__u8 off;

			// TCP or UDP found
			if (key.proto == GADGET_SE_NEXTHDR_TCP ||
			    key.proto == GADGET_SE_NEXTHDR_UDP)
				break;

			err = bpf_skb_load_bytes(skb, l4_off, &nextproto,
						 sizeof(nextproto));
			if (err < 0)
				return 0;

			// Unfortunately, each extension header has a different way to calculate the header length.
			// Support the ones defined in ipv6_ext_hdr(). See ipv6_skip_exthdr().
			switch (key.proto) {
			case GADGET_SE_NEXTHDR_FRAGMENT:
				// No hdrlen in the fragment header
				l4_off += 8;
				break;
			case GADGET_SE_NEXTHDR_AUTH:
				// See ipv6_authlen()
				err = bpf_skb_load_bytes(skb, l4_off + 1, &off,
							 sizeof(off));
				if (err < 0)
					return 0;
				l4_off += 4 * (off + 2);
				break;
			case GADGET_SE_NEXTHDR_HOP:
			case GADGET_SE_NEXTHDR_ROUTING:
			case GADGET_SE_NEXTHDR_DEST:
				// See ipv6_optlen()
				err = bpf_skb_load_bytes(skb, l4_off + 1, &off,
							 sizeof(off));
				if (err < 0)
					return 0;
				l4_off += 8 * (off + 1);
				break;
			case GADGET_SE_NEXTHDR_NONE:
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

	int off = l4_off;
	switch (key.proto) {
	case IPPROTO_TCP:
		if (is_ingress)
			off += GADGET_SE_TCPHDR_DEST_OFFSET;
		else
			off += GADGET_SE_TCPHDR_SOURCE_OFFSET;
		break;
	case IPPROTO_UDP:
		if (is_ingress)
			off += GADGET_SE_UDPHDR_DEST_OFFSET;
		else
			off += GADGET_SE_UDPHDR_SOURCE_OFFSET;
		break;
	default:
		return 0;
	}

	err = bpf_skb_load_bytes(skb, off, &key.port, sizeof(key.port));
	if (err < 0)
		return 0;
	key.port = bpf_ntohs(key.port);

	ret = bpf_map_lookup_elem(&gadget_sockets, &key);
	if (ret)
		return ret;

	// If a native socket was not found, try to find a dual-stack socket.
	if (key.family == GADGET_SE_AF_INET) {
		key.family = GADGET_SE_AF_INET6;
		ret = bpf_map_lookup_elem(&gadget_sockets, &key);
		if (ret && ret->ipv6only == 0)
			return ret;
	}

	return 0;
}

// Helper to lookup a socket based using skb->pkt_type.
// This shouldn't be used with TC program because in certain cases (e.g CNIs)
// the skb->pkt_type will be set to GADGET_SE_PACKET_HOST since the packet is destined
// for the host because it needs to be routed via host. In such cases, use
// gadget_socket_lookup_with_direction() instead.
static __always_inline struct gadget_socket_value *
gadget_socket_lookup(const struct __sk_buff *skb)
{
	__u8 is_ingress = (skb->pkt_type == GADGET_SE_PACKET_HOST);
	return gadget_socket_lookup_with_direction(skb, is_ingress);
}
#endif

#ifdef GADGET_TYPE_TRACING
static __always_inline struct gadget_socket_value *
gadget_socket_lookup(const struct sock *sk, __u32 netns)
{
	struct gadget_socket_key key = {
		0,
	};
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

	return bpf_map_lookup_elem(&gadget_sockets, &key);
}
#endif

static __always_inline void
gadget_process_populate_from_socket(const struct gadget_socket_value *skb_val,
				    struct gadget_process *p)
{
	if (!skb_val)
		return;

	__builtin_memcpy(p->comm, skb_val->task, sizeof(p->comm));
	p->pid = skb_val->pid_tgid >> 32;
	p->tid = skb_val->pid_tgid;
	p->mntns_id = skb_val->mntns;

	p->creds.uid = skb_val->uid_gid;
	p->creds.gid = skb_val->uid_gid >> 32;

	__builtin_memcpy(p->parent.comm, skb_val->ptask,
			 sizeof(p->parent.comm));
	p->parent.pid = skb_val->ppid;
	p->parent.tid = skb_val->ptid;
}

#endif
