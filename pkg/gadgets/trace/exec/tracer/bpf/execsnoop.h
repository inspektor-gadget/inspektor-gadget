/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __EXECSNOOP_H
#define __EXECSNOOP_H

#define ARGSIZE 256
#define TASK_COMM_LEN 16
#define TOTAL_MAX_ARGS 20
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)
#define INVALID_UID ((uid_t) - 1)
#define BASE_EVENT_SIZE (size_t)(&((struct event *)0)->args)
#define EVENT_SIZE(e) (BASE_EVENT_SIZE + e->args_size)
#define LAST_ARG (FULL_MAX_ARGS_ARR - ARGSIZE)

// this needs to be manually kept in sync with execsnoopEventAbbrev in tracer.go (without the args field)
struct event {
	__u64 mntns_id;
	__u64 timestamp;
	__u32 pid;
	__u32 tid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
	__u32 loginuid;
	__u32 sessionid;
	int retval;
	int args_count;
	bool upper_layer;
	bool pupper_layer;
	unsigned int args_size;
	__u8 comm[TASK_COMM_LEN];
	__u8 pcomm[TASK_COMM_LEN];
#ifdef WITH_LONG_PATHS
	__u8 cwd[MAX_STRING_SIZE];
	__u8 exepath[MAX_STRING_SIZE];
#endif
	__u8 args[FULL_MAX_ARGS_ARR];
};

#endif /* __EXECSNOOP_H */
