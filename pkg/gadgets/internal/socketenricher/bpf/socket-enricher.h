
/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0 */

#ifndef SOCKET_ENRICHER_H
#define SOCKET_ENRICHER_H

#ifdef SOCKETS_MAP_IMPLEMENTATION
#error "include socket-enricher.h in your own bpf programs"
#endif

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// current_netns is automatically set to the correct value in userspace with
// RewriteConstants()
const volatile __u32 current_netns = 0;

typedef __u32 ipv4_addr;

// Placeholder functions that will be replaced by the real implementation in
// extension.bpf.c
//
// Use a volatile ret variable to ensure the compiler does not optimise away
// the return value in the caller.
//
// Use the argument skb to ensure the compiler does not optimise away the
// argument stacking in the caller.

__attribute__((noinline)) __u64 gadget_skb_get_mntns(struct __sk_buff *skb) {
	volatile int ret = skb != NULL;
	return ret;
}

__attribute__((noinline)) __u64 gadget_skb_get_pid_tgid(struct __sk_buff *skb) {
	volatile int ret = skb != NULL;
	return ret;
}

__attribute__((noinline)) __u64 gadget_skb_get_comm1(struct __sk_buff *skb) {
	volatile int ret = skb != NULL;
	return ret;
}

__attribute__((noinline)) __u64 gadget_skb_get_comm2(struct __sk_buff *skb) {
	volatile int ret = skb != NULL;
	return ret;
}

#endif
