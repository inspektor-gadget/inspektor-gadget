/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __EXECRUNTIME_H
#define __EXECRUNTIME_H

#define ARGSIZE 256
#define TASK_COMM_LEN 16
#define TOTAL_MAX_ARGS 20
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)
#define INVALID_UID ((uid_t) - 1)
#define BASE_EVENT_SIZE (size_t)(&((struct event *)0)->args)
#define EVENT_SIZE(e) (BASE_EVENT_SIZE + e->args_size)
#define LAST_ARG (FULL_MAX_ARGS_ARR - ARGSIZE)

struct record {
	__u64 mntns_id;
	__u32 pid;
	unsigned int args_size;
	__u8 caller_comm[TASK_COMM_LEN];
	__u8 args[FULL_MAX_ARGS_ARR];
};

// exec_event is emitted once per successful execve so userspace can re-attach
// uprobes to a container's settled executable. pid is the tgid (the process
// that completed the execve), which is the container init PID for an in-place
// wrapper exec (e.g. node:20-slim's docker-entrypoint.sh exec'ing node).
struct exec_event {
	__u64 mntns_id;
	__u32 pid;
};

#endif /* __EXECRUNTIME_H */
