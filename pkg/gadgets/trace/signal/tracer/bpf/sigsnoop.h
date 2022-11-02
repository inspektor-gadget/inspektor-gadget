/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __SIGSNOOP_H
#define __SIGSNOOP_H

#define TASK_COMM_LEN	16

struct event {
	__u32 pid;
	__u32 tpid;
	__u64 mntns_id;
	int sig;
	int ret;
	__u8 comm[TASK_COMM_LEN];
};

#endif /* __SIGSNOOP_H */
