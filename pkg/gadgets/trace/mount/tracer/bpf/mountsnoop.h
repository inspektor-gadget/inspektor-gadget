/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __MOUNTSNOOP_H
#define __MOUNTSNOOP_H

#define TASK_COMM_LEN	16
#define FS_NAME_LEN	8
#define DATA_LEN	512
#define PATH_MAX	4096

enum op {
	MOUNT,
	UMOUNT,
};

struct arg {
	__u64 ts;
	__u64 flags;
	const char *src;
	const char *dest;
	const char *fs;
	const char *data;
	enum op op;
};

struct event {
	__u64 delta;
	__u64 flags;
	__u32 pid;
	__u32 tid;
	__u64 mount_ns_id;
	__u64 timestamp;
	int ret;
	__u8 comm[TASK_COMM_LEN];
	__u8 fs[FS_NAME_LEN];
	__u8 src[PATH_MAX];
	__u8 dest[PATH_MAX];
	__u8 data[DATA_LEN];
	enum op op;
};

#endif /* __MOUNTSNOOP_H */
