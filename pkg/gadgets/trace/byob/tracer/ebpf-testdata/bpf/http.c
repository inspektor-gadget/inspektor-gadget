// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021-2022 The Inspektor Gadget authors */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

//#include <sys/socket.h>
#ifndef AF_INET
#define AF_INET 2
#endif

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <socket-enricher.h>

typedef __u32 ipv4_addr;

#define TASK_COMM_LEN	16

struct event_t {
	__u64 mount_ns_id;
	__u32 pid;
	__u32 tid;
	char task[TASK_COMM_LEN];

	ipv4_addr saddr_v4;
	ipv4_addr daddr_v4;
	__u32 af; // AF_INET or AF_INET6

	__u32 pkt_type;

	char verb[16];
};

#define TCP_OFF (ETH_HLEN + sizeof(struct iphdr))

unsigned long long load_byte(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.word");

// we need this to make sure the compiler doesn't remove our struct
const struct event_t *unusedevent __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(value, struct event_t);
} events SEC(".maps");


SEC("socket1")
int ig_trace_http(struct __sk_buff *skb)
{
	// Skip non-IP packets
	if (load_half(skb, offsetof(struct ethhdr, h_proto)) != ETH_P_IP)
		return 0;

	// Skip non-TCP packets
	if (load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol)) != IPPROTO_TCP)
		return 0;

	struct event_t event = {0,};
	event.af = AF_INET;
	event.daddr_v4 = load_word(skb, ETH_HLEN + offsetof(struct iphdr, daddr));
	event.saddr_v4 = load_word(skb, ETH_HLEN + offsetof(struct iphdr, saddr));
	// load_word converts from network to host endianness. Convert back to
	// network endianness because inet_ntop() requires it.
	event.daddr_v4 = bpf_htonl(event.daddr_v4);
	event.saddr_v4 = bpf_htonl(event.saddr_v4);

	// Read the TCP header.
	struct tcphdr tcph;
	if (bpf_skb_load_bytes(skb, TCP_OFF, &tcph, sizeof tcph))
		return 0;

	if (!tcph.psh)
		return 0;

	// The data offset field in the header is specified in 32-bit words. We
	// have to multiply this value by 4 to get the TCP header length in bytes.
	__u8 tcp_header_len = tcph.doff * 4;
	// TLS data starts at this offset.
	int payload_off = TCP_OFF + tcp_header_len;

	int err = bpf_skb_load_bytes(skb, payload_off, event.verb, sizeof(event.verb));
	if (err != 0) {
		return 0;
	}
	if (event.verb[0] != 'G' || event.verb[1] != 'E' || event.verb[2] != 'T') {
		return 0;
	}
	event.verb[15] = 0;

	event.pkt_type = skb->pkt_type;

	// Enrich event with process metadata
	event.mount_ns_id = gadget_skb_get_mntns(skb);
	__u64 pid_tgid = gadget_skb_get_pid_tgid(skb);
	event.pid = pid_tgid >> 32;
	event.tid = (__u32)pid_tgid;
	*(__u64*)event.task = gadget_skb_get_comm1(skb);
	*(__u64*)(event.task+8) = gadget_skb_get_comm2(skb);

	bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	return 0;
}

char _license[] SEC("license") = "GPL";
