// SPDX-License-Identifier: GPL-2.0

#ifndef __TCPDROP_H
#define __TCPDROP_H

#define TASK_COMM_LEN 16

struct proc_ctx {
	__u64 mount_ns_id;
	__u32 pid;
	__u32 tid;
	__u8 task[TASK_COMM_LEN];
};

struct event {
	union {
		__u8 saddr[16];
		unsigned __int128 saddr_v6;
		__u32 saddr_v4;
	};
	union {
		__u8 daddr[16];
		unsigned __int128 daddr_v6;
		__u32 daddr_v4;
	};
	__u64 timestamp;
	__u32 af; // AF_INET or AF_INET6
	__u16 dport;
	__u16 sport;
	__u8 state;
	__u8 tcpflags;
	__u32 reason;
	__u32 netns;

	struct proc_ctx proc_current;
	struct proc_ctx proc_socket;
};


#endif /* __TCPDROP_H */
