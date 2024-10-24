// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>

/* Since LSM hooks may change with different kernel versions, here we only list the common ones.
 * TODO: Implement best-effort mechanism and add the remaining ones,
 * this requires an upstream support: https://github.com/cilium/ebpf/discussions/1470
 */
#define FOR_EACH_LSM_HOOK(F)        \
	F(binder_set_context_mgr)   \
	F(binder_transaction)       \
	F(binder_transfer_binder)   \
	F(binder_transfer_file)     \
	F(ptrace_access_check)      \
	F(ptrace_traceme)           \
	F(capget)                   \
	F(capset)                   \
	F(capable)                  \
	F(quotactl)                 \
	F(quota_on)                 \
	F(syslog)                   \
	F(settime)                  \
	F(vm_enough_memory)         \
	F(bprm_creds_for_exec)      \
	F(bprm_creds_from_file)     \
	F(bprm_check_security)      \
	F(bprm_committing_creds)    \
	F(bprm_committed_creds)     \
	F(fs_context_dup)           \
	F(fs_context_parse_param)   \
	F(sb_alloc_security)        \
	F(sb_delete)                \
	F(sb_free_security)         \
	F(sb_free_mnt_opts)         \
	F(sb_eat_lsm_opts)          \
	F(sb_mnt_opts_compat)       \
	F(sb_remount)               \
	F(sb_kern_mount)            \
	F(sb_show_options)          \
	F(sb_statfs)                \
	F(sb_mount)                 \
	F(sb_umount)                \
	F(sb_pivotroot)             \
	F(sb_set_mnt_opts)          \
	F(sb_clone_mnt_opts)        \
	F(move_mount)               \
	F(dentry_init_security)     \
	F(dentry_create_files_as)   \
	F(path_notify)              \
	F(inode_alloc_security)     \
	F(inode_free_security)      \
	F(inode_init_security)      \
	F(inode_init_security_anon) \
	F(inode_create)             \
	F(inode_link)               \
	F(inode_unlink)             \
	F(inode_symlink)            \
	F(inode_mkdir)              \
	F(inode_rmdir)              \
	F(inode_mknod)              \
	F(inode_rename)             \
	F(inode_readlink)           \
	F(inode_follow_link)        \
	F(inode_permission)         \
	F(inode_setattr)            \
	F(inode_getattr)            \
	F(inode_setxattr)           \
	F(inode_post_setxattr)      \
	F(inode_getxattr)           \
	F(inode_listxattr)          \
	F(inode_removexattr)        \
	F(inode_need_killpriv)      \
	F(inode_killpriv)           \
	F(inode_getsecurity)        \
	F(inode_setsecurity)        \
	F(inode_listsecurity)       \
	F(inode_getsecid)           \
	F(inode_copy_up)            \
	F(inode_copy_up_xattr)      \
	F(kernfs_init_security)     \
	F(file_permission)          \
	F(file_alloc_security)      \
	F(file_free_security)       \
	F(file_ioctl)               \
	F(mmap_addr)                \
	F(mmap_file)                \
	F(file_mprotect)            \
	F(file_lock)                \
	F(file_fcntl)               \
	F(file_set_fowner)          \
	F(file_send_sigiotask)      \
	F(file_receive)             \
	F(file_open)                \
	F(task_alloc)               \
	F(task_free)                \
	F(cred_alloc_blank)         \
	F(cred_free)                \
	F(cred_prepare)             \
	F(cred_transfer)            \
	F(cred_getsecid)            \
	F(kernel_act_as)            \
	F(kernel_create_files_as)   \
	F(kernel_module_request)    \
	F(kernel_load_data)         \
	F(kernel_post_load_data)    \
	F(kernel_read_file)         \
	F(kernel_post_read_file)    \
	F(task_fix_setuid)          \
	F(task_fix_setgid)          \
	F(task_setpgid)             \
	F(task_getpgid)             \
	F(task_getsid)              \
	F(task_getsecid_obj)        \
	F(task_setnice)             \
	F(task_setioprio)           \
	F(task_getioprio)           \
	F(task_prlimit)             \
	F(task_setrlimit)           \
	F(task_setscheduler)        \
	F(task_getscheduler)        \
	F(task_movememory)          \
	F(task_kill)                \
	F(task_prctl)               \
	F(task_to_inode)            \
	F(ipc_permission)           \
	F(ipc_getsecid)             \
	F(msg_msg_alloc_security)   \
	F(msg_msg_free_security)    \
	F(msg_queue_alloc_security) \
	F(msg_queue_free_security)  \
	F(msg_queue_associate)      \
	F(msg_queue_msgctl)         \
	F(msg_queue_msgsnd)         \
	F(msg_queue_msgrcv)         \
	F(shm_alloc_security)       \
	F(shm_free_security)        \
	F(shm_associate)            \
	F(shm_shmctl)               \
	F(shm_shmat)                \
	F(sem_alloc_security)       \
	F(sem_free_security)        \
	F(sem_associate)            \
	F(sem_semctl)               \
	F(sem_semop)                \
	F(netlink_send)             \
	F(d_instantiate)            \
	F(getprocattr)              \
	F(setprocattr)              \
	F(ismaclabel)               \
	F(secid_to_secctx)          \
	F(secctx_to_secid)          \
	F(release_secctx)           \
	F(inode_invalidate_secctx)  \
	F(inode_notifysecctx)       \
	F(inode_setsecctx)          \
	F(inode_getsecctx)

#define ENUM_ITEM(name) name,

enum lsm_tracepoint { FOR_EACH_LSM_HOOK(ENUM_ITEM) };

struct event {
	gadget_timestamp timestamp_raw;
	gadget_mntns_id mntns_id;

	gadget_comm comm[TASK_COMM_LEN];
	// user-space terminology for pid and tid
	gadget_pid pid;
	gadget_tid tid;
	gadget_uid uid;
	gadget_gid gid;

	enum lsm_tracepoint tracepoint_raw;
};

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(lsm, events, event);

#define DECLARE_LSM_PARAMETER(name)               \
	const volatile bool trace_##name = false; \
	GADGET_PARAM(trace_##name);

const volatile bool trace_all = true;
GADGET_PARAM(trace_all);

FOR_EACH_LSM_HOOK(DECLARE_LSM_PARAMETER)

#define TRACE_LSM(name)                                                \
	SEC("lsm/" #name)                                              \
	int trace_lsm_##name()                                         \
	{                                                              \
		struct event event;                                    \
		u64 mntns_id;                                          \
		u64 pid_tgid;                                          \
		u64 uid_gid;                                           \
                                                                       \
		if (!trace_##name && !trace_all)                       \
			return 0;                                      \
                                                                       \
		mntns_id = gadget_get_mntns_id();                      \
		if (gadget_should_discard_mntns_id(mntns_id))          \
			return 0;                                      \
                                                                       \
		pid_tgid = bpf_get_current_pid_tgid();                 \
		uid_gid = bpf_get_current_uid_gid();                   \
                                                                       \
		event.mntns_id = mntns_id;                             \
		event.timestamp_raw = bpf_ktime_get_boot_ns();         \
		event.pid = pid_tgid >> 32;                            \
		event.tid = pid_tgid;                                  \
		event.uid = uid_gid;                                   \
		event.gid = uid_gid >> 32;                             \
		event.tracepoint_raw = name;                           \
		bpf_get_current_comm(event.comm, sizeof(event.comm));  \
                                                                       \
		bpf_ringbuf_output(&events, &event, sizeof(event), 0); \
		return 0;                                              \
	}

FOR_EACH_LSM_HOOK(TRACE_LSM)

char LICENSE[] SEC("license") = "Dual BSD/GPL";
