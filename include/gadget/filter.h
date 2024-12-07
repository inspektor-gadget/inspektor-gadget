/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0 */

#ifndef FILTER_H
#define FILTER_H

#include <bpf/bpf_helpers.h>
#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/mntns_filter.h>

#define GADGET_INVALID_ID ((uid_t)-1)

// user space terminology
const volatile gadget_pid targ_pid = 0;
GADGET_PARAM(targ_pid);

const volatile gadget_tid targ_tid = 0;
GADGET_PARAM(targ_tid);

const volatile gadget_uid targ_uid = GADGET_INVALID_ID;
GADGET_PARAM(targ_uid);

const volatile gadget_gid targ_gid = GADGET_INVALID_ID;
GADGET_PARAM(targ_gid);

const volatile gadget_comm targ_comm[TASK_COMM_LEN] = {};
GADGET_PARAM(targ_comm);

static __always_inline bool gadget_should_discard_pid_tid(gadget_pid pid,
							  gadget_tid tid)
{
	if (targ_pid != 0 && targ_pid != pid)
		return true;

	if (targ_tid != 0 && targ_tid != tid)
		return true;

	return false;
}

static __always_inline bool gadget_should_discard_uid_gid(gadget_uid uid,
							  gadget_gid gid)
{
	if (targ_uid != GADGET_INVALID_ID && targ_uid != uid)
		return true;

	if (targ_gid != GADGET_INVALID_ID && targ_gid != gid)
		return true;

	return false;
}

static __always_inline bool
gadget_should_discard_comm(gadget_comm comm[TASK_COMM_LEN])
{
	if (targ_comm[0] == '\0')
		return false;

	for (int i = 0; i < TASK_COMM_LEN; i++) {
		if (comm[i] != targ_comm[i])
			return true;
	}

	return false;
}

// gadget_should_discard returns true if the gadget should skip this event.
static __always_inline bool
gadget_should_discard(gadget_mntns_id mntns_id, gadget_pid pid, gadget_tid tid,
		      gadget_comm comm[TASK_COMM_LEN], gadget_uid uid,
		      gadget_uid gid)
{
	if (gadget_should_discard_mntns_id(mntns_id))
		return true;

	if (gadget_should_discard_pid_tid(pid, tid))
		return true;

	if (gadget_should_discard_uid_gid(uid, gid))
		return true;

	if (gadget_should_discard_comm(comm))
		return true;

	return false;
}

// gadget_should_discard_current returns true if the gadget should drop this
// event. This function uses the current mount namespace, pid, tid, uid, and gid
// to determine if the event should be dropped.
// This function is implemented in a way that it returns as soon as possible to
// avoid unnecesary operations, hence there is some code duplication with the
// gadget_should_discard function.
static __always_inline bool gadget_should_discard_current()
{
	if (gadget_should_discard_mntns_id(gadget_get_mntns_id()))
		return true;

	if (targ_pid != 0 || targ_tid != 0) {
		// user space terminology used here
		__u64 pid_tgid = bpf_get_current_pid_tgid();
		__u32 pid = pid_tgid >> 32;
		__u32 tid = pid_tgid;

		if (gadget_should_discard_pid_tid(pid, tid))
			return true;
	}

	if (targ_uid != GADGET_INVALID_ID || targ_gid != GADGET_INVALID_ID) {
		__u64 uid_gid = bpf_get_current_uid_gid();
		__u32 uid = uid_gid;
		__u32 gid = uid_gid >> 32;

		if (gadget_should_discard_uid_gid(uid, gid))
			return true;
	}

	if (targ_comm[0] != '\0') {
		char comm[TASK_COMM_LEN];
		bpf_get_current_comm(&comm, sizeof(comm));
		if (gadget_should_discard_comm(comm))
			return true;
	}

	return false;
}

#endif
