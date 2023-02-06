/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0 */

#ifndef SOCKETS_MAP_H
#define SOCKETS_MAP_H

#ifndef SOCKETS_MAP_IMPLEMENTATION

#include <linux/if_ether.h>
#include <linux/ip.h>
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

const volatile __u32 current_netns = 0;

unsigned long long load_byte(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.word");

#define L4_OFF (ETH_HLEN + sizeof(struct iphdr))

typedef __u32 ipv4_addr;

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
};

#define MAX_SOCKETS	16384
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SOCKETS);
	__type(key, struct sockets_key);
	__type(value, struct sockets_value);
} sockets SEC(".maps");

static __always_inline struct sockets_value *
gadget_socket_lookup(struct __sk_buff *skb)
{
	// Only IPv4 is supported for now
	if (load_half(skb, offsetof(struct ethhdr, h_proto)) != ETH_P_IP)
		return 0;

	struct sockets_key key = {0,};
	key.netns = current_netns;
	key.family = AF_INET;
	key.proto = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
	switch (key.proto) {
	case IPPROTO_TCP:
		if (skb->pkt_type == PACKET_HOST)
			key.port = load_half(skb, L4_OFF + offsetof(struct tcphdr, dest));
		else
			key.port = load_half(skb, L4_OFF + offsetof(struct tcphdr, source));
		break;
	case IPPROTO_UDP:
		if (skb->pkt_type == PACKET_HOST)
			key.port = load_half(skb, L4_OFF + offsetof(struct udphdr, dest));
		else
			key.port = load_half(skb, L4_OFF + offsetof(struct udphdr, source));
		break;
	default:
		return 0;
	}

	return bpf_map_lookup_elem(&sockets, &key);
}

#endif
