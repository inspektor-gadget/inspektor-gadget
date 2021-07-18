// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 The Inspektor Gadget authors */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* llvm builtin functions that eBPF C program may use to
 * emit BPF_LD_ABS and BPF_LD_IND instructions
 */
unsigned long long load_byte(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.word");

#ifndef printt
#define printt(fmt, ...)                                                \
  ({                                                                    \
    char ____fmt[] = fmt;                                               \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);          \
  })
#endif


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, char[255]);
	__uint(max_entries, 128);
} context SEC(".maps");

SEC("socket1")
int bpf_prog1(struct __sk_buff *skb)
{
	// Skip non-IP packets
	if (load_half(skb, offsetof(struct ethhdr, h_proto)) != ETH_P_IP)
		return 0;

	// Skip non-UDP packets
        if (load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol)) != IPPROTO_UDP)
                return 0;

	int dns_off = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr);
	
	// Skip non DNS Query packets
	// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
        if (load_byte(skb, dns_off + 2) != 0x01) // recursive
                return 0;
        if (load_byte(skb, dns_off + 3) != 0x00)
                return 0;

	// Max DNS name length: 255
	// https://datatracker.ietf.org/doc/html/rfc1034#section-3.1
	int parts_cur = 0;
	int i;
	int len;
	int skip = 0;
	int off;
	for (i = 0; i < 255 ; i++) {
		if (skip != 0) {
			int content = load_byte(skb, dns_off + 12 + i);
			printt("UDP payload: %d", content);
			skip--;
		} else {
			len = load_byte(skb, dns_off + 12 + i);
			if (len == 0)
				break;
			skip = len;
			parts_cur++;
		}
	}

	printt("UDP payload: %d parts", parts_cur);

	return 0;
}

char _license[] SEC("license") = "GPL";
