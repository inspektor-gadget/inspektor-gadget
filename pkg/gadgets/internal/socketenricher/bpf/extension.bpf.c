// SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0
/* Copyright (c) 2022 The Inspektor Gadget authors */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "sockets-map.h"

#define L4_OFF (ETH_HLEN + sizeof(struct iphdr))

unsigned long long load_byte(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.word");

// Linux only supports scalars and pointers to ctx (e.g. 'struct __sk_buff *'
// for socket filter) in bpf extensions so we can't pass all fields in one
// call. 
//
// This might have a small performance penalty, but this is easier than using a
// separate ring buffer to send the metadata in userspace.

static __always_inline struct sockets_value *
socket_lookup(struct __sk_buff *skb)
{
	struct sockets_key key = {0,};
	key.netns = current_netns;
	key.proto = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
	if (key.proto == IPPROTO_TCP) {
		if (skb->pkt_type == PACKET_HOST)
			key.port = load_half(skb, L4_OFF + offsetof(struct tcphdr, dest));
		else
			key.port = load_half(skb, L4_OFF + offsetof(struct tcphdr, source));
	} else if (key.proto == IPPROTO_UDP) {
		if (skb->pkt_type == PACKET_HOST)
			key.port = load_half(skb, L4_OFF + offsetof(struct udphdr, dest));
		else
			key.port = load_half(skb, L4_OFF + offsetof(struct udphdr, source));
	} else {
		return 0;
	}

	return bpf_map_lookup_elem(&sockets, &key);
}

SEC("freplace/gadget_skb_get_mntns") __u64 gadget_skb_get_mntns(struct __sk_buff *skb) {
	struct sockets_value *socketp = socket_lookup(skb);
	if (socketp != NULL) {
		return socketp->mntns;
	}
	return 0;
}

SEC("freplace/gadget_skb_get_pid_tgid") __u64 gadget_skb_get_pid_tgid(struct __sk_buff *skb) {
	struct sockets_value *socketp = socket_lookup(skb);
	if (socketp != NULL) {
		return socketp->pid_tgid;
	}
	return 0;
}

SEC("freplace/gadget_skb_get_comm1") __u64 gadget_skb_get_comm1(struct __sk_buff *skb) {
	struct sockets_value *socketp = socket_lookup(skb);
	if (socketp != NULL) {
		return *(__u64*)socketp->task;
	}
	return 0;
}

SEC("freplace/gadget_skb_get_comm2") __u64 gadget_skb_get_comm2(struct __sk_buff *skb) {
	struct sockets_value *socketp = socket_lookup(skb);
	if (socketp != NULL) {
		return *(__u64*)(socketp->task+8);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
