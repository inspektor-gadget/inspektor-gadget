// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 The Inspektor Gadget authors

#ifndef __USER_STACK_MAP_H
#define __USER_STACK_MAP_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include <gadget/types.h>
#include <gadget/macros.h>

const volatile bool collect_ustack = false;
GADGET_PARAM(collect_ustack);

#define USER_MAX_STACK_DEPTH 127
#define USER_STACK_MAP_MAX_ENTRIES 10000

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, USER_MAX_STACK_DEPTH * sizeof(u64));
	__uint(max_entries, USER_STACK_MAP_MAX_ENTRIES);
} ig_ustack SEC(".maps");

// Linux v4.0 - v4.17
struct timespec___obsolete {
	__kernel_old_time_t tv_sec;
	long tv_nsec;
};
struct inode___with_timespec {
	struct timespec___obsolete i_mtime;
};

// Linux v4.18 - v6.6
// https://github.com/torvalds/linux/commit/95582b00838837fc07e042979320caf917ce3fe6
struct inode___with_timespec64 {
	struct timespec64 i_mtime;
};

// Linux 6.7 - v6.10
// https://github.com/torvalds/linux/commit/12cd44023651666bd44baa36a5c999698890debb
struct inode___with_timespec64_underscore {
	struct timespec64 __i_mtime;
};

// Linux v6.11 - v6.14-rc2
// https://github.com/torvalds/linux/commit/3aa63a569c64e708df547a8913c84e64a06e7853
struct inode___with_two_fields {
	time64_t i_mtime_sec;
	u32 i_mtime_nsec;
};

static __always_inline void
gadget_inode_get_mtime(struct inode *inode, __u64 *mtime_sec, __u32 *mtime_nsec)
{
	// There are 4 variants for the mtime fields in the inode struct. They can
	// vary by name, by type, and/or both. So we need to check both the name
	// (bpf_core_field_exists) and the type (bpf_core_field_size) of the field.

	// Linux v6.11 - v6.14-rc2
	// https://github.com/torvalds/linux/commit/3aa63a569c64e708df547a8913c84e64a06e7853
	if (bpf_core_field_exists(struct inode___with_two_fields,
				  i_mtime_sec) &&
	    bpf_core_field_size(struct inode___with_two_fields, i_mtime_sec) ==
		    sizeof(time64_t)) {
		struct inode___with_two_fields *inode_with_two_fields =
			(struct inode___with_two_fields *)inode;
		*mtime_sec = BPF_CORE_READ(inode_with_two_fields, i_mtime_sec);
		*mtime_nsec =
			BPF_CORE_READ(inode_with_two_fields, i_mtime_nsec);

		return;
	}

	// Linux 6.7 - v6.10
	// https://github.com/torvalds/linux/commit/12cd44023651666bd44baa36a5c999698890debb
	if (bpf_core_field_exists(struct inode___with_timespec64_underscore,
				  __i_mtime) &&
	    bpf_core_field_size(struct inode___with_timespec64_underscore,
				__i_mtime) == sizeof(struct timespec64)) {
		struct inode___with_timespec64_underscore
			*inode_with_timespec64_underscore =
				(struct inode___with_timespec64_underscore *)
					inode;
		*mtime_sec = BPF_CORE_READ(inode_with_timespec64_underscore,
					   __i_mtime.tv_sec);
		*mtime_nsec = BPF_CORE_READ(inode_with_timespec64_underscore,
					    __i_mtime.tv_nsec);

		return;
	}

	// Linux v4.18 - v6.6
	// https://github.com/torvalds/linux/commit/95582b00838837fc07e042979320caf917ce3fe6
	if (bpf_core_field_exists(struct inode___with_timespec64, i_mtime) &&
	    bpf_core_field_size(struct inode___with_timespec64, i_mtime) ==
		    sizeof(struct timespec64)) {
		struct inode___with_timespec64 *inode_with_timespec64 =
			(struct inode___with_timespec64 *)inode;
		*mtime_sec =
			BPF_CORE_READ(inode_with_timespec64, i_mtime.tv_sec);
		*mtime_nsec =
			BPF_CORE_READ(inode_with_timespec64, i_mtime.tv_nsec);

		return;
	}

	// Linux v4.0 - v4.17
	if (bpf_core_field_exists(struct inode___with_timespec, i_mtime) &&
	    bpf_core_field_size(struct inode___with_timespec, i_mtime) ==
		    sizeof(struct timespec___obsolete)) {
		struct inode___with_timespec *inode_with_timespec =
			(struct inode___with_timespec *)inode;
		*mtime_sec = BPF_CORE_READ(inode_with_timespec, i_mtime.tv_sec);
		*mtime_nsec =
			BPF_CORE_READ(inode_with_timespec, i_mtime.tv_nsec);

		return;
	}
}

/* gadget_get_user_stack gets the user stack into ustack if collect_ustack is
 * true, or initialize ustack to 0 otherwise.
 */
static __always_inline void
gadget_get_user_stack(void *ctx, struct gadget_user_stack *ustack)
{
	if (!collect_ustack) {
		ustack->stack_id = 0;
		ustack->exe_inode = 0;
		ustack->pid_level0 = 0;
		ustack->pidns_level0 = 0;
		ustack->pid_level1 = 0;
		ustack->pidns_level1 = 0;
		return;
	}
	ustack->stack_id = bpf_get_stackid(
		ctx, &ig_ustack, BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK);

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct inode *inode = BPF_CORE_READ(task, mm, exe_file, f_inode);
	ustack->exe_inode = (u64)BPF_CORE_READ(inode, i_ino);

	struct pid *thread_pid = BPF_CORE_READ(task, thread_pid);
	unsigned int level = BPF_CORE_READ(thread_pid, level);
	// Cast pointer to "struct upid *" to avoid compilation warning in a way
	// that works both on Linux < v6.5 and >= v6.5. See:
	// https://github.com/torvalds/linux/commit/b69f0aeb068980af983d399deafc7477cec8bc04
	struct upid *numbers = (struct upid *)&thread_pid->numbers;

	ustack->pid_level0 = BPF_CORE_READ(numbers, nr);
	ustack->pidns_level0 = BPF_CORE_READ(numbers, ns, ns.inum);
	if (level >= 1) {
		numbers += 1;
		ustack->pid_level1 = BPF_CORE_READ(numbers, nr);
		ustack->pidns_level1 = BPF_CORE_READ(numbers, ns, ns.inum);
	} else {
		ustack->pid_level1 = 0;
		ustack->pidns_level1 = 0;
	}

	gadget_inode_get_mtime(inode, &ustack->mtime_sec, &ustack->mtime_nsec);
}

#endif /* __STACK_MAP_H */
