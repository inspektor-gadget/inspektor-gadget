/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0 */

#ifndef SOCKETS_MAP_H
#define SOCKETS_MAP_H

#ifndef SOCKETS_MAP_IMPLEMENTATION

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

const volatile __u64 current_netns = 0;

#endif

#ifndef PACKET_HOST
#define PACKET_HOST		0
#endif

#ifdef PACKET_OUTGOING
#define PACKET_OUTGOING		4
#endif


typedef __u32 ipv4_addr;

struct sockets_key {
	__u64 netns;

	// proto is IPPROTO_TCP(6) or IPPROTO_UDP(17)
	__u16 proto;
	__u16 port;
};

#define TASK_COMM_LEN	16
struct sockets_value {
	__u64 mntns;
	__u32 pid;
	__u32 tid;
	char task[TASK_COMM_LEN];

	// 0 = client (connect)
	// 1 = server (bind)
	__u32 server;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct sockets_key);
	__type(value, struct sockets_value);
#ifdef SOCKETS_MAP_IMPLEMENTATION
} sockets SEC(".maps");
#else
} sockets SEC(".maps.auto");
#endif

#ifndef SOCKETS_MAP_IMPLEMENTATION

#define L4_OFF (ETH_HLEN + sizeof(struct iphdr))

/* llvm builtin functions that eBPF C program may use to
 * emit BPF_LD_ABS and BPF_LD_IND instructions
 */
unsigned long long load_byte(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.word");

static __always_inline int
enrich_with_process(struct __sk_buff *skb, struct sockets_value *meta)
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

	struct sockets_value *socketp = bpf_map_lookup_elem(&sockets, &key);
	if (socketp != NULL) {
		meta->mntns = socketp->mntns;
		meta->pid = socketp->pid;
		meta->tid = socketp->tid;
		__builtin_memcpy(&meta->task, socketp->task, sizeof(meta->task));
	} else {
	}
	return 0;
}
#endif

#endif
