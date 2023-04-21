/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TCPCONNLAT_H
#define __TCPCONNLAT_H

#define TASK_COMM_LEN	16

struct event {
	union {
		__u8 saddr_v6[16];
		__u32 saddr_v4;
	};
	union {
		__u8 daddr_v6[16];
		__u32 daddr_v4;
	};
	__u8 comm[TASK_COMM_LEN];
	__u64 timestamp;
	__u64 mntns_id;
	__u64 delta;
	// tgid and pid from kernel point of view
	__u32 tgid;
	__u32 pid;
	int af;
	__u16 lport;
	__u16 dport;
};


#endif /* __TCPCONNLAT_H_ */
