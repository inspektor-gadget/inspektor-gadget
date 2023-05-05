// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//
// Copyright 2022 Sony Group Corporation

#ifndef __CAPABLE_H
#define __CAPABLE_H

#define TASK_COMM_LEN	16

#ifndef BIT
#define BIT(nr) (1UL << (nr))
#endif /* !BIT */

/*
 * Taken from:
 * https://github.com/torvalds/linux/blob/78b421b6a7c6/include/linux/security.h#L67-L69
 */
#ifndef CAP_OPT_NOAUDIT
#define CAP_OPT_NOAUDIT BIT(1)
#endif /* !CAP_OPT_NOAUDIT */

#ifndef CAP_OPT_INSETID
#define CAP_OPT_INSETID BIT(2)
#endif /* !CAP_OPT_INSETID */

struct cap_event {
	__u64	mntnsid;
	__u64	current_userns;
	__u64	target_userns;
	__u64 cap_effective;
	__u64 timestamp;
	__u32	pid;
	int	cap;
	__u32	tgid;
	__u32	uid;
	int	ret;
	int	audit;
	int	insetid;
	__u64	syscall;
	__u8	task[TASK_COMM_LEN];
};

#endif /* __CAPABLE_H */
