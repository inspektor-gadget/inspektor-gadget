// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 The Inspektor Gadget authors */

// Avoid CO-RE:
// CO-RE relocations: relocate struct#35["iphdr"]: target struct#49626["iphdr"]: target struct#49626["iphdr"]: field "ihl" is a bitfield: not supported 
// 
// #include <vmlinux/vmlinux.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "graph.h"

#ifndef ETH_P_IP
#define ETH_P_IP	0x0800
#endif

#ifndef ETH_HLEN
#define ETH_HLEN	14
#endif

#ifndef PACKET_HOST
#define PACKET_HOST		0		/* To us		*/
#endif

#ifdef PACKET_OUTGOING
#define PACKET_OUTGOING		4		/* Outgoing of any type */
#endif

const volatile u64 container_quark = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct graph_key_t);
	__type(value, char);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} graphmap SEC(".maps");

SEC("socket1")
int bpf_prog1(struct __sk_buff *skb)
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

	// Skip packets with IP protocol other than TCP.
	if (iph.protocol != IPPROTO_TCP)
		return 0;

	// An IPv4 header doesn't have a fixed size. The IHL field of a packet
	// represents the size of the IP header in 32-bit words, so we need to
	// multiply this value by 4 to get the header size in bytes.
	__u8 ip_header_len = iph.ihl * 4;
	int tcp_off = ip_off + ip_header_len;

	// Read the TCP header.
	struct tcphdr tcph;
	if (bpf_skb_load_bytes(skb, tcp_off, &tcph, sizeof tcph))
		return 0;

	if (!tcph.syn || tcph.ack)
		return 0;

	struct graph_key_t key = {};
	key.container_quark	= container_quark;
	key.pkt_type		= skb->pkt_type;
	key.proto		= iph.protocol;
	key.port		= tcph.dest;
	if (skb->pkt_type == PACKET_HOST) {
		key.ip		= iph.saddr;
	} else {
		key.ip		= iph.daddr;
	}
	char zero = 0;

	bpf_map_update_elem(&graphmap, &key, &zero, BPF_ANY);

	return 0;
}

struct bpf_iter_meta {
	__bpf_md_ptr(struct seq_file *, seq);
	__u64 session_id;
	__u64 seq_num;
};

struct bpf_iter__bpf_map_elem {
	__bpf_md_ptr(struct bpf_iter_meta *, meta);
	__bpf_md_ptr(struct bpf_map *, map);
	__bpf_md_ptr(void *, key);
	__bpf_md_ptr(void *, value);
};

/* From: tools/lib/bpf/bpf_tracing.h */
/*
 * BPF_SEQ_PRINTF to wrap bpf_seq_printf to-be-printed values
 * in a structure.
 */
#define BPF_SEQ_PRINTF(seq, fmt, args...)                                  \
       ({                                                                  \
               _Pragma("GCC diagnostic push")                              \
               _Pragma("GCC diagnostic ignored \"-Wint-conversion\"")      \
               static const char ___fmt[] = fmt;                           \
               unsigned long long ___param[] = { args };                   \
               _Pragma("GCC diagnostic pop")                               \
               int ___ret = bpf_seq_printf(seq, ___fmt, sizeof(___fmt),    \
                                           ___param, sizeof(___param));    \
               ___ret;                                                     \
       })


SEC("iter/bpf_map_elem")
int dump_graph(struct bpf_iter__bpf_map_elem *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	__u32 seq_num = ctx->meta->seq_num;
	struct bpf_map *map = ctx->map;
	struct graph_key_t *key = ctx->key;
	struct graph_key_t tmp_key;
	char *val = ctx->value;

	if (key == (void *)0 || val == (void *)0) {
		return 0;
	}

	BPF_SEQ_PRINTF(seq, "%u %u %u %u ",
		key->container_quark,
		key->pkt_type,
		key->proto,
		bpf_htons(key->port));
	BPF_SEQ_PRINTF(seq, "%pI4\n", &key->ip);

	__builtin_memcpy(&tmp_key, key, sizeof(struct graph_key_t));
	bpf_map_delete_elem(&graphmap, &tmp_key);

	return 0;
}

char _license[] SEC("license") = "GPL";
