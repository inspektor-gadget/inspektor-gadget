#ifndef GADGET_AUDIT_SECCOMP_H
#define GADGET_AUDIT_SECCOMP_H

#define TASK_COMM_LEN 16

struct event {
	__u64 pid;
	__u64 mntns_id;
	__u64 timestamp;
	__u64 syscall;
	__u64 code;
	__u8 comm[TASK_COMM_LEN];
};

#endif
