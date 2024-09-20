/* SPDX-License-Identifier: Apache-2.0 */

#ifndef __COMMON_H
#define __COMMON_H

#include <vmlinux.h>
#include <gadget/types.h>
#include <gadget/mntns.h>
#include <bpf/bpf_helpers.h>

// gadget_process_populate fills the given process struct with the current
// process information.
void static __always_inline gadget_process_populate(struct gadget_process *p) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	p->pid = pid_tgid >> 32;
	p->tid = pid_tgid;
	bpf_get_current_comm(p->comm, sizeof(p->comm));

	p->creds.uid = uid_gid;
	p->creds.gid = uid_gid >> 32;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	p->mntns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	if (parent == NULL)
		return;

	bpf_probe_read_kernel(&p->parent.comm, sizeof(p->parent.comm), parent->comm);
	p->parent.pid = BPF_CORE_READ(parent, tgid);
}

#endif
