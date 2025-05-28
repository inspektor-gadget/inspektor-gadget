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
// Redefine the constants we need but namespaced (SE_) so we don't pollute gadgets.

#define SE_PACKET_HOST 0
#define SE_ETH_HLEN 14
#define SE_ETH_P_IP 0x0800 /* Internet Protocol packet     */
#define SE_ETH_P_IPV6 0x86DD /* IPv6 over bluebook           */
#define SE_AF_INET 2 /* Internet IP Protocol 	*/
#define SE_AF_INET6 10 /* IP version 6                 */

#define SE_IPV6_HLEN 40
#define SE_IPV6_NEXTHDR_OFFSET 6 // offsetof(struct ipv6hdr, nexthdr)

#define SE_TCPHDR_DEST_OFFSET 2 // offsetof(struct tcphdr, dest);
#define SE_TCPHDR_SOURCE_OFFSET 0 // offsetof(struct tcphdr, source);
#define SE_UDPHDR_DEST_OFFSET 2 // offsetof(struct udphdr, dest);
#define SE_UDPHDR_SOURCE_OFFSET 0 // offsetof(struct udphdr, source);

#define SE_NEXTHDR_HOP 0 /* Hop-by-hop option header. */
#define SE_NEXTHDR_TCP 6 /* TCP segment. */
#define SE_NEXTHDR_UDP 17 /* UDP message. */
#define SE_NEXTHDR_ROUTING 43 /* Routing header. */
#define SE_NEXTHDR_FRAGMENT 44 /* Fragmentation/reassembly header. */
#define SE_NEXTHDR_AUTH 51 /* Authentication header. */
#define SE_NEXTHDR_NONE 59 /* No next header */
#define SE_NEXTHDR_DEST 60 /* Destination options header. */

struct sockets_key {
	__u32 netns;
	__u16 family;

	// proto is IPPROTO_TCP(6) or IPPROTO_UDP(17)
	__u8 proto;
	__u16 port;
};

#define MAX_SOCKETS 16384
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SOCKETS);
	__type(key, __u64);
	__type(value, struct sockets_value);
} gadget_sockets SEC(".maps");

#ifdef GADGET_TYPE_NETWORKING
static __always_inline struct sockets_value *
gadget_socket_lookup(const struct __sk_buff *skb)
{
	__u64 key = bpf_get_socket_cookie((void*)skb);
	return bpf_map_lookup_elem(&gadget_sockets, &key);
	return 0;
}
#endif

#ifdef GADGET_TYPE_TRACING
static __always_inline struct sockets_value *
gadget_socket_lookup(const struct sock *sk, __u32 netns)
{
	__u64 key = BPF_CORE_READ(sk, __sk_common.skc_cookie.counter);
	return bpf_map_lookup_elem(&gadget_sockets, &key);
}
#endif

static __always_inline void
gadget_process_populate_from_socket(const struct sockets_value *skb_val,
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
}

#endif
