#ifndef GADGET_AUDIT_SECCOMP_H
#define GADGET_AUDIT_SECCOMP_H

#ifdef __TARGET_ARCH_arm64
#include "../../../../arm64/vmlinux/vmlinux-cgo.h"
#else
// In several case (e.g. make test), we compile this file without having set
// BPF_ARCH, so we default to include amd64 vmlinux.h.
// For other architecture, like arm64, we use __TARGET_ARCH_arch to
// differentiate.
#include "../../../../amd64/vmlinux/vmlinux-cgo.h"
#endif

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
