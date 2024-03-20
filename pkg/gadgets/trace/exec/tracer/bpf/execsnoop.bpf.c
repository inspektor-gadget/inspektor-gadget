// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#ifdef __TARGET_ARCH_arm64
#include <bpf/bpf_tracing.h>
#endif /* __TARGET_ARCH_arm64 */

#include <gadget/mntns_filter.h>
#ifdef WITH_LONG_PATHS
#include <gadget/filesystem.h>
#endif
#include "execsnoop.h"

// Defined in include/uapi/linux/magic.h
#define OVERLAYFS_SUPER_MAGIC 0x794c7630

const volatile bool ignore_failed = true;
const volatile uid_t targ_uid = INVALID_UID;
const volatile int max_args = DEFAULT_MAXARGS;

static const struct event empty_event = {};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
#ifdef WITH_CWD
	__uint(max_entries, 1024);
#else /* !WITH_CWD */
	__uint(max_entries, 10240);
#endif /* !WITH_CWD */
	__type(key, pid_t);
	__type(value, struct event);
} execs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

// man clone(2):
//   If any of the threads in a thread group performs an
//   execve(2), then all threads other than the thread group
//   leader are terminated, and the new program is executed in
//   the thread group leader.
//
// sys_enter_execve might be called from a thread and the corresponding
// sys_exit_execve will be called from the thread group leader in case of
// execve success, or from the same thread in case of execve failure. So we
// need to lookup the pid from the tgid in sys_exit_execve.
//
// We don't know in advance which execve(2) will succeed, so we need to keep
// track of all tgid<->pid mappings in a BPF map.
//
// We don't want to use bpf_for_each_map_elem() because it requires Linux 5.13.
//
// If several execve(2) are performed in parallel from different threads, only
// one can succeed. The kernel will run the tracepoint syscalls/sys_exit_execve
// for the failing execve(2) first and then for the successful one last.
//
// So we can insert a tgid->pid mapping in the same hash entry by modulo adding
// the pid in value and removing it by subtracting. By the time we need to
// lookup the pid by the tgid, there will be only one pid left in the hash entry.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t); // tgid
	__type(value, u64); // sum of pids
	__uint(max_entries, 1024);
} pid_by_tgid SEC(".maps");

static __always_inline bool valid_uid(uid_t uid)
{
	return uid != INVALID_UID;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int ig_execve_e(struct syscall_trace_enter *ctx)
{
	u64 id;
	char *cwd;
	pid_t pid, tgid;
	u64 zero64 = 0;
	u64 *pid_sum;
	struct event *event;
	struct fs_struct *fs;
	struct task_struct *task;
	unsigned int ret;
	const char **args = (const char **)(ctx->args[1]);
	const char *argp;
	int i;
	u64 mntns_id;
	u64 uid_gid = bpf_get_current_uid_gid();
	u32 uid = (u32)uid_gid;
	u32 gid = (u32)(uid_gid >> 32);

	if (valid_uid(targ_uid) && targ_uid != uid)
		return 0;

	task = (struct task_struct *)bpf_get_current_task();
	mntns_id = (u64)BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	id = bpf_get_current_pid_tgid();
	pid = (pid_t)id;
	tgid = id >> 32;
	if (bpf_map_update_elem(&execs, &pid, &empty_event, BPF_NOEXIST))
		return 0;

	event = bpf_map_lookup_elem(&execs, &pid);
	if (!event)
		return 0;

	bpf_map_update_elem(&pid_by_tgid, &tgid, &zero64, BPF_NOEXIST);

	pid_sum = bpf_map_lookup_elem(&pid_by_tgid, &tgid);
	if (!pid_sum)
		return 0;

	__atomic_add_fetch(pid_sum, (u64)pid, __ATOMIC_RELAXED);

	event->timestamp = bpf_ktime_get_boot_ns();
	event->pid = tgid;
	event->uid = uid;
	event->gid = gid;
	// loginuid is only available when CONFIG_AUDIT is set
	if (bpf_core_field_exists(task->loginuid))
		event->loginuid = BPF_CORE_READ(task, loginuid.val);
	else
		event->loginuid = 4294967295; // -1 or "no user id"
	// sessionid is only available when CONFIG_AUDIT is set
	if (bpf_core_field_exists(task->sessionid))
		event->sessionid = BPF_CORE_READ(task, sessionid);

	event->ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
	event->args_count = 0;
	event->args_size = 0;
	event->mntns_id = mntns_id;

#ifdef WITH_LONG_PATHS
	fs = BPF_CORE_READ(task, fs);
	cwd = get_path_str(&fs->pwd);
	bpf_probe_read_kernel_str(event->cwd, MAX_STRING_SIZE, cwd);
#endif

	ret = bpf_probe_read_user_str(event->args, ARGSIZE,
				      (const char *)ctx->args[0]);
	if (ret <= ARGSIZE) {
		event->args_size += ret;
	} else {
		/* write an empty string */
		event->args[0] = '\0';
		event->args_size++;
	}

	event->args_count++;
#pragma unroll
	for (i = 1; i < TOTAL_MAX_ARGS && i < max_args; i++) {
		bpf_probe_read_user(&argp, sizeof(argp), &args[i]);
		if (!argp)
			return 0;

		if (event->args_size > LAST_ARG)
			return 0;

		ret = bpf_probe_read_user_str(&event->args[event->args_size],
					      ARGSIZE, argp);
		if (ret > ARGSIZE)
			return 0;

		event->args_count++;
		event->args_size += ret;
	}
	/* try to read one more argument to check if there is one */
	bpf_probe_read_user(&argp, sizeof(argp), &args[max_args]);
	if (!argp)
		return 0;

	/* pointer to max_args+1 isn't null, asume we have more arguments */
	event->args_count++;
	return 0;
}

static __always_inline bool has_upper_layer()
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct inode *inode = BPF_CORE_READ(task, mm, exe_file, f_inode);
	if (!inode) {
		return false;
	}
	unsigned long sb_magic = BPF_CORE_READ(inode, i_sb, s_magic);

	if (sb_magic != OVERLAYFS_SUPER_MAGIC) {
		return false;
	}

	struct dentry *upperdentry;

	// struct ovl_inode defined in fs/overlayfs/ovl_entry.h
	// Unfortunately, not exported to vmlinux.h
	// and not available in /sys/kernel/btf/vmlinux
	// See https://github.com/cilium/ebpf/pull/1300
	// We only rely on vfs_inode and __upperdentry relative positions
	bpf_probe_read_kernel(&upperdentry, sizeof(upperdentry),
			      ((void *)inode) +
				      bpf_core_type_size(struct inode));
	return upperdentry != NULL;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int ig_execve_x(struct syscall_trace_exit *ctx)
{
	u64 id;
	pid_t pid, tgid;
	pid_t execs_lookup_key;
	u64 *pid_sum;
	int ret;
	struct event *event;
	u32 uid = (u32)bpf_get_current_uid_gid();
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	struct file *exe_file;
	char *exepath;

	if (valid_uid(targ_uid) && targ_uid != uid)
		return 0;
	id = bpf_get_current_pid_tgid();
	pid = (pid_t)id;
	tgid = id >> 32;
	ret = ctx->ret;

	pid_sum = bpf_map_lookup_elem(&pid_by_tgid, &tgid);
	if (!pid_sum)
		return 0;

	// sys_enter_execve and sys_exit_execve might be called from different
	// threads. We need to lookup the pid from the tgid.
	execs_lookup_key = (ret == 0) ? (pid_t)*pid_sum : pid;
	event = bpf_map_lookup_elem(&execs, &execs_lookup_key);

	// Remove the tgid->pid mapping if the value reaches 0
	// or the execve() call was successful
	__atomic_add_fetch(pid_sum, (u64)-pid, __ATOMIC_RELAXED);
	if (*pid_sum == 0 || ret == 0)
		bpf_map_delete_elem(&pid_by_tgid, &tgid);

	if (!event)
		return 0;
	if (ignore_failed && ret < 0)
		goto cleanup;

	if (ret == 0) {
		event->upper_layer = has_upper_layer();
	}

	event->retval = ret;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	if (parent != NULL)
		bpf_probe_read_kernel(&event->pcomm, sizeof(event->pcomm),
				      parent->comm);

#ifdef WITH_LONG_PATHS
	exe_file = BPF_CORE_READ(task, mm, exe_file);
	exepath = get_path_str(&exe_file->f_path);
	bpf_probe_read_kernel_str(event->exepath, MAX_STRING_SIZE, exepath);
#endif

	size_t len = EVENT_SIZE(event);
	if (len <= sizeof(*event))
		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
				      len);
cleanup:
	bpf_map_delete_elem(&execs, &execs_lookup_key);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
