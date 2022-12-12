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

#ifdef PACKET_OUTGOING
#define PACKET_OUTGOING		4
#endif


typedef __u32 ipv4_addr;

struct sockets_key {
	__u32 netns;

	// proto is IPPROTO_TCP(6) or IPPROTO_UDP(17)
	__u16 proto;
	__u16 port;
};

#define TASK_COMM_LEN	16
struct sockets_value {
	__u64 mntns;
	__u64 pid_tgid;
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

#endif
