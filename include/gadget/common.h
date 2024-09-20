/* SPDX-License-Identifier: Apache-2.0 */

#ifndef __COMMON_H
#define __COMMON_H

#include <bpf/bpf_helpers.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct user {
	__u32 uid;
	__u32 gid;
};

struct process {
	char comm[TASK_COMM_LEN];
	__u32 pid;
	__u32 tid;

	struct user user;
};

// gadget_fill_current_process fills the given process struct with the current
// process information.
void static __always_inline gadget_fill_current_process(struct process *p) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	p->pid = pid_tgid >> 32;
	p->tid = pid_tgid;
	bpf_get_current_comm(p->comm, sizeof(p->comm));

	p->user.uid = uid_gid;
	p->user.gid = uid_gid >> 32;
}

#endif
