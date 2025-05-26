// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define GADGET_NO_BUF_RESERVE
#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/filesystem.h>

// Defined in include/uapi/linux/magic.h
#define OVERLAYFS_SUPER_MAGIC 0x794c7630

#define ARGSIZE 256
#define TOTAL_MAX_ARGS 20

// Keep in sync with fullMaxArgsArr in program.go
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)

#define BASE_EVENT_SIZE (size_t)(&((struct event *)0)->args)
#define EVENT_SIZE(e) (BASE_EVENT_SIZE + e->args_size)
#define LAST_ARG (FULL_MAX_ARGS_ARR - ARGSIZE)

// Macros from https://github.com/torvalds/linux/blob/v6.12/include/linux/kdev_t.h#L7-L12
#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)
#define MAJOR(dev) ((unsigned int)((dev) >> MINORBITS))
#define MINOR(dev) ((unsigned int)((dev) & MINORMASK))
#define MKDEV(ma, mi) (((ma) << MINORBITS) | (mi))

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;

	gadget_uid loginuid;
	__u32 sessionid;
	gadget_errno error_raw;
	int args_count;
	bool upper_layer;
	bool fupper_layer;
	bool pupper_layer;
	unsigned int args_size;
	char cwd[GADGET_PATH_MAX];
	char file[GADGET_PATH_MAX];
	unsigned int dev_major;
	unsigned int dev_minor;
	unsigned long inode;
	char exepath[GADGET_PATH_MAX];
	char parent_exepath[GADGET_PATH_MAX];
	char args[FULL_MAX_ARGS_ARR];
};

const volatile bool ignore_failed = true;
const volatile bool paths = false;

GADGET_PARAM(ignore_failed);
GADGET_PARAM(paths);

static const struct event empty_event = {};

// man clone(2):
//   If any of the threads in a thread group performs an
//   execve(2), then all threads other than the thread group
//   leader are terminated, and the new program is executed in
//   the thread group leader.
//
// sys_enter_execve might be called from a thread and the corresponding
// sys_exit_execve will be called from the thread group leader in case of
// execve success, or from the same thread in case of execve failure.
//
// Moreover, checking ctx->ret == 0 is not a reliable way to distinguish
// successful execve from failed execve because seccomp can change ctx->ret.
//
// Therefore, use two different tracepoints to handle the map cleanup:
// - tracepoint/sched/sched_process_exec is called after a successful execve
// - tracepoint/syscalls/sys_exit_execve is always called
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, pid_t);
	__type(value, struct event);
} execs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, pid_t);
	__type(value, __u8);
} security_bprm_hit_map SEC(".maps");

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(exec, events, event);

static __always_inline int enter_execve(const char *pathname, const char **args)
{
	u64 id;
	pid_t pid;
	struct event *event;
	struct task_struct *task;
	unsigned int ret;
	const char *argp;
	int i;

	if (gadget_should_discard_data_current())
		return 0;

	id = bpf_get_current_pid_tgid();
	pid = (pid_t)id;
	if (bpf_map_update_elem(&execs, &pid, &empty_event, BPF_NOEXIST))
		return 0;

	event = bpf_map_lookup_elem(&execs, &pid);
	if (!event)
		return 0;

	event->timestamp_raw = bpf_ktime_get_boot_ns();
	task = (struct task_struct *)bpf_get_current_task();

	// loginuid is only available when CONFIG_AUDIT is set
	if (bpf_core_field_exists(task->loginuid))
		event->loginuid = BPF_CORE_READ(task, loginuid.val);
	else
		event->loginuid = 4294967295; // -1 or "no user id"

	// sessionid is only available when CONFIG_AUDIT is set
	if (bpf_core_field_exists(task->sessionid))
		event->sessionid = BPF_CORE_READ(task, sessionid);

	event->args_count = 0;
	event->args_size = 0;

	if (paths) {
		struct fs_struct *fs = BPF_CORE_READ(task, fs);
		char *cwd = get_path_str(&fs->pwd);
		bpf_probe_read_kernel_str(event->cwd, sizeof(event->cwd), cwd);
	}

	ret = bpf_probe_read_user_str(event->args, ARGSIZE, pathname);
	if (ret <= ARGSIZE) {
		event->args_size += ret;
	} else {
		/* write an empty string */
		event->args[0] = '\0';
		event->args_size++;
	}

	event->args_count++;
#pragma unroll
	for (i = 1; i < TOTAL_MAX_ARGS; i++) {
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
	bpf_probe_read_user(&argp, sizeof(argp), &args[TOTAL_MAX_ARGS]);
	if (!argp)
		return 0;

	/* pointer to max_args+1 isn't null, assume we have more arguments */
	event->args_count++;
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int ig_execve_e(struct syscall_trace_enter *ctx)
{
	const char *pathname = (const char *)ctx->args[0];
	const char **args = (const char **)(ctx->args[1]);
	return enter_execve(pathname, args);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int ig_execveat_e(struct syscall_trace_enter *ctx)
{
	const char *pathname = (const char *)ctx->args[1];
	const char **args = (const char **)(ctx->args[2]);
	return enter_execve(pathname, args);
}

static __always_inline bool has_upper_layer(struct inode *inode)
{
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
	bpf_probe_read_kernel(&upperdentry, sizeof upperdentry,
			      ((void *)inode) +
				      bpf_core_type_size(struct inode));

	return upperdentry != NULL;
}

// tracepoint/sched/sched_process_exec is called after a successful execve
SEC("tracepoint/sched/sched_process_exec")
int ig_sched_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	u32 pre_sched_pid = ctx->old_pid;
	struct event *event;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);

	event = bpf_map_lookup_elem(&execs, &pre_sched_pid);
	if (!event)
		return 0;

	struct inode *inode = BPF_CORE_READ(task, mm, exe_file, f_inode);
	if (inode)
		event->upper_layer = has_upper_layer(inode);

	struct inode *pinode = BPF_CORE_READ(parent, mm, exe_file, f_inode);
	if (pinode)
		event->pupper_layer = has_upper_layer(pinode);

	gadget_process_populate(&event->proc);
	event->error_raw = 0;

	if (paths) {
		struct file *exe_file = BPF_CORE_READ(task, mm, exe_file);
		char *exepath = get_path_str(&exe_file->f_path);
		bpf_probe_read_kernel_str(event->exepath,
					  sizeof(event->exepath), exepath);

		struct file *parent_exe_file =
			BPF_CORE_READ(parent, mm, exe_file);
		char *parent_exepath = get_path_str(&parent_exe_file->f_path);
		bpf_probe_read_kernel_str(event->parent_exepath,
					  sizeof(event->parent_exepath),
					  parent_exepath);
	}

	size_t len = EVENT_SIZE(event);
	if (len <= sizeof(*event))
		gadget_output_buf(ctx, &events, event, len);

	bpf_map_delete_elem(&execs, &pre_sched_pid);
	bpf_map_delete_elem(&security_bprm_hit_map, &pre_sched_pid);

	return 0;
}

static __always_inline int exit_execve(void *ctx, int retval)
{
	u32 pid = (u32)bpf_get_current_pid_tgid();
	struct event *event;

	// If the execve was successful, sched/sched_process_exec handled the event
	// already and deleted the entry. So if we find the entry, it means the
	// the execve failed.
	event = bpf_map_lookup_elem(&execs, &pid);
	if (!event)
		return 0;

	if (ignore_failed)
		goto cleanup;

	gadget_process_populate(&event->proc);
	event->error_raw = -retval;

	if (paths) {
		struct task_struct *task =
			(struct task_struct *)bpf_get_current_task();
		struct file *exe_file = BPF_CORE_READ(task, mm, exe_file);
		char *exepath = get_path_str(&exe_file->f_path);
		bpf_probe_read_kernel_str(event->exepath,
					  sizeof(event->exepath), exepath);
	}

	size_t len = EVENT_SIZE(event);
	if (len <= sizeof(*event))
		gadget_output_buf(ctx, &events, event, len);
cleanup:
	bpf_map_delete_elem(&execs, &pid);
	bpf_map_delete_elem(&security_bprm_hit_map, &pid);
	return 0;
}

// We use syscalls/sys_exit_execve only to trace failed execve
// This program is needed regardless of ignore_failed
SEC("tracepoint/syscalls/sys_exit_execve")
int ig_execve_x(struct syscall_trace_exit *ctx)
{
	return exit_execve(ctx, ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int ig_execveat_x(struct syscall_trace_exit *ctx)
{
	return exit_execve(ctx, ctx->ret);
}

SEC("kprobe/security_bprm_check")
int BPF_KPROBE(security_bprm_check, struct linux_binprm *bprm)
{
	u32 pid = (u32)bpf_get_current_pid_tgid();
	struct event *event;
	char *file;
	dev_t dev_no;
	struct path f_path;

	event = bpf_map_lookup_elem(&execs, &pid);
	if (!event)
		return 0;

	// security_bprm_check is called repeatedly following the shebang
	// Only get the first call.
	__u8 *exists = bpf_map_lookup_elem(&security_bprm_hit_map, &pid);
	if (exists) {
		return 0;
	}

	__u8 hit = 1;
	if (bpf_map_update_elem(&security_bprm_hit_map, &pid, &hit,
				BPF_NOEXIST)) {
		return 0;
	}

	struct inode *inode = BPF_CORE_READ(bprm, file, f_inode);
	if (inode)
		event->fupper_layer = has_upper_layer(inode);

	if (paths) {
		f_path = BPF_CORE_READ(bprm, file, f_path);
		file = get_path_str(&f_path);
		bpf_probe_read_kernel_str(event->file, sizeof(event->file),
					  file);

		dev_no = BPF_CORE_READ(inode, i_sb, s_dev);
		event->dev_major = MAJOR(dev_no);
		event->dev_minor = MINOR(dev_no);
		event->inode = BPF_CORE_READ(inode, i_ino);
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
