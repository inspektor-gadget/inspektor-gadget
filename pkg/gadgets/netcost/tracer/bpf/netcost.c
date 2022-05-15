// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 The Inspektor Gadget authors */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/if_packet.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "netcost.h"

/* llvm builtin functions that eBPF C program may use to
 * emit BPF_LD_ABS and BPF_LD_IND instructions
 */
unsigned long long load_byte(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.word");

// TODO: This LPM_TRIE definition does not work with BTF
//struct {
//	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
//	__type(key, __u64); // int + IPv4
//	__type(value, struct cidr_stats);
//	__uint(max_entries, 256);
//	__uint(map_flags, BPF_F_NO_PREALLOC);
//} lpm_stats SEC(".maps");

struct bpf_map_def SEC("maps") lpm_stats = {
	.type		= BPF_MAP_TYPE_LPM_TRIE,
	.key_size	= 8, // int + IPv4
	.value_size	= sizeof(struct cidr_stats),
	.max_entries	= 256,
	.map_flags	= BPF_F_NO_PREALLOC,
};

SEC("socket1")
int bpf_prog1(struct __sk_buff *skb)
{
	__u64 nhoff = ETH_HLEN;

	if (load_half(skb, offsetof(struct ethhdr, h_proto)) != ETH_P_IP)
		return 0;

	__u32 lpm_key[2];
	struct cidr_stats *value;

	lpm_key[0] = 32;

	if (skb->pkt_type == PACKET_OUTGOING) {
		int ret = bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, daddr), &lpm_key[1], 4);
		if (ret < 0)
			return 0;
	} else {
		int ret = bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, saddr), &lpm_key[1], 4);
		if (ret < 0)
			return 0;
	}
	value = bpf_map_lookup_elem(&lpm_stats, lpm_key);

	if (!value)
		return 0;

	if (skb->pkt_type == PACKET_OUTGOING) {
		__sync_fetch_and_add(&value->bytes_sent, skb->len);
		__sync_fetch_and_add(&value->packets_sent, 1);
	} else {
		__sync_fetch_and_add(&value->bytes_recv, skb->len);
		__sync_fetch_and_add(&value->packets_recv, 1);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
