// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//
// Copyright 2022 Sony Group Corporation

#ifndef __CAPABLE_H
#define __CAPABLE_H

#define TASK_COMM_LEN	16

struct cap_event {
	__u64	mntnsid;
	__u32	pid;
	int	cap;
	__u32	tgid;
	__u32	uid;
	int	cap_opt;
	int	ret;
	char	task[TASK_COMM_LEN];
};

enum uniqueness {
	UNQ_OFF, UNQ_PID, UNQ_CGROUP
};

#endif /* __CAPABLE_H */
