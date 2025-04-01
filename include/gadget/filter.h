/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0 */

// This file defines some helpers to filter events based on different common
// fields like pid, tid, uid, gid, comm and containers. Be aware that user space
// terminology is used on this file: pid here refers to the task group id (tgid)
// on kernel lingo and tid refers to pid on kernel lingo.

#ifndef FILTER_H
#define FILTER_H

#include <bpf/bpf_helpers.h>
#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/mntns_filter.h>
#ifndef GADGET_TYPE_NETWORKING
#include <gadget/mntns.h>
#endif

#define GADGET_INVALID_ID ((gadget_uid) - 1)

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

static __always_inline bool gadget_should_discard_pid(gadget_pid pid)
{
	return targ_pid != 0 && targ_pid != pid;
}

static __always_inline bool gadget_should_discard_tid(gadget_tid tid)
{
	return targ_tid != 0 && targ_tid != tid;
}

static __always_inline bool gadget_should_discard_uid(gadget_uid uid)
{
	return targ_uid != GADGET_INVALID_ID && targ_uid != uid;
}

static __always_inline bool gadget_should_discard_gid(gadget_gid gid)
{
	return targ_gid != GADGET_INVALID_ID && targ_gid != gid;
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

// gadget_should_discard_data returns true if the gadget should skip this event.
static __always_inline bool
gadget_should_discard_data(gadget_mntns_id mntns_id, gadget_pid pid,
			   gadget_tid tid, gadget_comm comm[TASK_COMM_LEN],
			   gadget_uid uid, gadget_uid gid)
{
	return gadget_should_discard_mntns_id(mntns_id) ||
	       gadget_should_discard_pid(pid) ||
	       gadget_should_discard_tid(tid) ||
	       gadget_should_discard_uid(uid) ||
	       gadget_should_discard_gid(gid) ||
	       gadget_should_discard_comm(comm);
}

#ifndef GADGET_TYPE_NETWORKING
// gadget_should_discard_data_current returns true if the gadget should drop
// this event. This function uses the current task mount namespace, pid, tid,
// uid, and gid to determine if the event should be dropped. This function is
// implemented in a way that it returns as soon as possible to avoid unnecessary
// operations, hence there is some code duplication with the
// gadget_should_discard_data function.
static __always_inline bool gadget_should_discard_data_current()
{
	if (gadget_should_discard_mntns_id(gadget_get_current_mntns_id()))
		return true;

	if (targ_pid != 0 || targ_tid != 0) {
		// user space terminology used here
		__u64 pid_tgid = bpf_get_current_pid_tgid();
		__u32 pid = pid_tgid >> 32;
		__u32 tid = pid_tgid;

		if (gadget_should_discard_pid(pid) ||
		    gadget_should_discard_tid(tid))
			return true;
	}

	if (targ_uid != GADGET_INVALID_ID || targ_gid != GADGET_INVALID_ID) {
		__u64 uid_gid = bpf_get_current_uid_gid();
		__u32 uid = uid_gid;
		__u32 gid = uid_gid >> 32;

		if (gadget_should_discard_uid(uid) ||
		    gadget_should_discard_gid(gid))
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

// gadget_should_discard_data_by_skb returns true if the gadget should skip this
// event based on the fields of the skb_val struct.
static __always_inline bool
gadget_should_discard_data_by_skb(struct sockets_value *skb_val)
{
	if (!skb_val) {
		// drop the packet if any filtering is specified
		if (gadget_filter_by_mntns || targ_pid != 0 || targ_tid != 0 ||
		    targ_uid != GADGET_INVALID_ID ||
		    targ_gid != GADGET_INVALID_ID || targ_comm[0] != '\0')
			return true;
		return false;
	}

	return gadget_should_discard_data(
		skb_val->mntns, skb_val->pid_tgid >> 32, skb_val->pid_tgid,
		skb_val->task, skb_val->uid_gid, skb_val->uid_gid >> 32);
}

#endif
