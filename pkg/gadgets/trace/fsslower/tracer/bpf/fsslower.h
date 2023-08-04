/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __FSSLOWER_H
#define __FSSLOWER_H

#define FILE_NAME_LEN 32
#define TASK_COMM_LEN 16

enum fs_file_op {
	F_READ,
	F_WRITE,
	F_OPEN,
	F_FSYNC,
	F_MAX_OP,
};

struct event {
	__u64 delta_us;
	__u64 end_ns;
	__s64 offset;
	__u64 size;
	__u64 mntns_id;
	__u64 timestamp;
	__u32 pid;
	enum fs_file_op op;
	__u8 file[FILE_NAME_LEN];
	__u8 task[TASK_COMM_LEN];
};

#endif /* __FSSLOWER_H */
