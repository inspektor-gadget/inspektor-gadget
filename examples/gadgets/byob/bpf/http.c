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

const volatile __u64 current_netns = 0;

typedef __u32 ipv4_addr;

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN	16
#endif

struct event_t {
	__u64 mount_ns_id;
	__u32 pid;
	char task[TASK_COMM_LEN];

	ipv4_addr saddr_v4;
	ipv4_addr daddr_v4;
	__u32 af; // AF_INET or AF_INET6

	__u32 pkt_type;

	char verb[16];
};

#define TCP_OFF (ETH_HLEN + sizeof(struct iphdr))

/* llvm builtin functions that eBPF C program may use to
 * emit BPF_LD_ABS and BPF_LD_IND instructions
 */
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

struct sockets_key {
	__u64 netns;

	// proto is IPPROTO_TCP(6) or IPPROTO_UDP(17)
	__u16 proto;
	__u16 port;
};

struct sockets_value {
	__u64 mntns;
	__u32 pid;
	char task[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct sockets_key);
	__type(value, struct sockets_value);
} sockets SEC(".maps.auto");

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
	struct sockets_key key = {0,};
	key.netns = current_netns;
	key.proto    = IPPROTO_TCP;
	key.port     = load_half(skb, TCP_OFF + offsetof(struct tcphdr, dest));

	bpf_printk("key.netns=%d proto=%d port=%d", key.netns, key.proto, key.port);

	struct sockets_value *socketp = bpf_map_lookup_elem(&sockets, &key);
	if (socketp != NULL) {
		event.mount_ns_id = socketp->mntns;
		event.pid = socketp->pid;
		__builtin_memcpy(&event.task, socketp->task, sizeof(event.task));
		bpf_printk("found %d", event.mount_ns_id);
	}

	bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	return 0;
}

char _license[] SEC("license") = "GPL";
