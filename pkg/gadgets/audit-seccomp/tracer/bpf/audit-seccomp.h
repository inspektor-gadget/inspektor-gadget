#ifndef GADGET_AUDIT_SECCOMP_H
#define GADGET_AUDIT_SECCOMP_H

#include "../../../../x86/vmlinux/vmlinux-cgo.h"
#define TASK_COMM_LEN 16

#include "../../../../gadgettracermanager/common.h"

struct event {
	u64 pid;
	u64 mntns_id;
	u64 syscall;
	u64 code;
	char comm[TASK_COMM_LEN];

	struct container container;
};

#endif
