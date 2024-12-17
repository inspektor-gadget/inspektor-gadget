/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __OPENSNOOP_H
#define __OPENSNOOP_H

#define TASK_COMM_LEN 16
#define NAME_MAX 255
#define PATH_MAX 4096
#define INVALID_UID ((uid_t) - 1)

struct start_t {
	int flags;
	__u16 mode;
	__u8 fname[NAME_MAX];
};

// this needs to be manually kept in sync with opensnoopEventAbbrev in tracer.go (without the full_fname field)
struct event {
	__u64 timestamp;
	/* user terminology for pid: */
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 gid;
	__u64 mntns_id;
	__s32 err;
	__u32 fd;
	int flags;
	__u16 mode;
	__u8 comm[TASK_COMM_LEN];
	__u8 fname[NAME_MAX];
	// Keep full_fname as the last field for optimization
	__u8 full_fname[PATH_MAX];
};

struct prefix_key {
	__u32 prefixlen;
	__u8 filename[NAME_MAX];
};

#endif /* __OPENSNOOP_H */
