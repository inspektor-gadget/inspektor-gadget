/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0 */

#ifndef SOCKETS_MAP_H
#define SOCKETS_MAP_H

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
	char task[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct sockets_key);
	__type(value, struct sockets_value);
} sockets SEC(".maps");

#endif
