// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//
// Copyright 2022 Sony Group Corporation

#ifndef __CAPABLE_H
#define __CAPABLE_H

#define TASK_COMM_LEN	16

struct cap_event {
	__u64	mntnsid;
	__u64	current_userns;
	__u64	target_userns;
	__u64   cap_effective;
	__u64 timestamp;
	__u32	pid;
	int	cap;
	__u32	tgid;
	__u32	uid;
	int	cap_opt;
	int	ret;
	__u64	syscall;
	__u8	task[TASK_COMM_LEN];
};

#endif /* __CAPABLE_H */
