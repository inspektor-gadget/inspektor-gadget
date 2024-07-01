// SPDX-License-Identifier: GPL-2.0
//
// Unique filtering based on
// https://github.com/libbpf/libbpf-rs/tree/master/examples/capable
//
// Copyright 2024 The Inspektor Gadget authors
// Copyright 2022 Sony Group Corporation

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/exec_fixes.h>
#include <gadget/kernel_stack_map.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>

// include/linux/security.h
#define CAP_OPT_NOAUDIT (1UL << 1)
#define CAP_OPT_INSETID (1UL << 2)

#define TASK_COMM_LEN 16

#define FOR_EACH_CAPABILITY(F)  \
	F(CAP_CHOWN)            \
	F(CAP_DAC_OVERRIDE)     \
	F(CAP_DAC_READ_SEARCH)  \
	F(CAP_FOWNER)           \
	F(CAP_FSETID)           \
	F(CAP_KILL)             \
	F(CAP_SETGID)           \
	F(CAP_SETUID)           \
	F(CAP_SETPCAP)          \
	F(CAP_LINUX_IMMUTABLE)  \
	F(CAP_NET_BIND_SERVICE) \
	F(CAP_NET_BROADCAST)    \
	F(CAP_NET_ADMIN)        \
	F(CAP_NET_RAW)          \
	F(CAP_IPC_LOCK)         \
	F(CAP_IPC_OWNER)        \
	F(CAP_SYS_MODULE)       \
	F(CAP_SYS_RAWIO)        \
	F(CAP_SYS_CHROOT)       \
	F(CAP_SYS_PTRACE)       \
	F(CAP_SYS_PACCT)        \
	F(CAP_SYS_ADMIN)        \
	F(CAP_SYS_BOOT)         \
	F(CAP_SYS_NICE)         \
	F(CAP_SYS_RESOURCE)     \
	F(CAP_SYS_TIME)         \
	F(CAP_SYS_TTY_CONFIG)   \
	F(CAP_MKNOD)            \
	F(CAP_LEASE)            \
	F(CAP_AUDIT_WRITE)      \
	F(CAP_AUDIT_CONTROL)    \
	F(CAP_SETFCAP)          \
	F(CAP_MAC_OVERRIDE)     \
	F(CAP_MAC_ADMIN)        \
	F(CAP_SYSLOG)           \
	F(CAP_WAKE_ALARM)       \
	F(CAP_BLOCK_SUSPEND)    \
	F(CAP_AUDIT_READ)       \
	F(CAP_PERFMON)          \
	F(CAP_BPF)              \
	F(CAP_CHECKPOINT_RESTORE)

enum capability {
#define LIST_CAPABILITY(CAP) CAP,
	FOR_EACH_CAPABILITY(LIST_CAPABILITY)
};

enum cap_effective_flags_set : __u64 {
#define LIST_CAPABILITY_FLAG(CAP) FLAG_##CAP = 1ULL << CAP,
	FOR_EACH_CAPABILITY(LIST_CAPABILITY_FLAG)
};

struct cap_event {
	gadget_mntns_id mntnsid;
	__u64 current_userns;
	__u64 target_userns;
	enum cap_effective_flags_set cap_effective_raw;
	gadget_timestamp timestamp_raw;
	__u32 pid;
	enum capability cap_raw;
	__u32 tgid;
	__u32 uid;
	__u32 gid;
	bool capable;
	int audit;
	int insetid;
	gadget_syscall syscall_raw;
	gadget_kernel_stack kstack_raw;
	char task[TASK_COMM_LEN];
};

#define MAX_ENTRIES 10240

const volatile bool audit_only = false;
GADGET_PARAM(audit_only);

const volatile bool unique = false;
GADGET_PARAM(unique);

extern int LINUX_KERNEL_VERSION __kconfig;

struct args_t {
	u64 current_userns;
	u64 target_userns;
	u64 cap_effective;
	int cap;
	int cap_opt;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u64);
	__type(value, struct args_t);
} start SEC(".maps");

struct unique_key {
	int cap;
	u64 mntns_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct unique_key);
	__type(value, u64);
} seen SEC(".maps");

struct syscall_context {
	// Syscall id
	// -1 for unknown syscall
	u64 nr;

	// We could add more fields for the arguments if desired
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(pid_t));
	__uint(value_size, sizeof(struct syscall_context));
	__uint(max_entries,
	       1048576); // There can be many threads sleeping in some futex/poll syscalls
} current_syscall SEC(".maps");

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(capabilities, events, cap_event);

const volatile bool print_stack = true;
GADGET_PARAM(print_stack);

SEC("kprobe/cap_capable")
int BPF_KPROBE(ig_trace_cap_e, const struct cred *cred,
	       struct user_namespace *targ_ns, int cap, int cap_opt)
{
	u64 mntns_id;
	__u64 pid_tgid;
	struct task_struct *task;

	task = (struct task_struct *)bpf_get_current_task();
	mntns_id = (u64)BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	const struct cred *real_cred = BPF_CORE_READ(task, real_cred);
	if (cred != real_cred) {
		// the subjective credentials are in an overridden state with
		// override_creds/revert_creds (e.g. during overlayfs cache or copyup)
		// https://kernel.org/doc/html/v6.2-rc8/security/credentials.html#overriding-the-vfs-s-use-of-credentials
		return 0;
	}

	pid_tgid = bpf_get_current_pid_tgid();

	if (audit_only) {
		if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 1, 0)) {
			if (cap_opt & CAP_OPT_NOAUDIT)
				return 0;
		} else {
			if (!cap_opt)
				return 0;
		}
	}

	if (unique) {
		struct unique_key key = {
			.cap = cap,
			.mntns_id = mntns_id,
		};

		if (bpf_map_lookup_elem(&seen, &key) != NULL) {
			return 0;
		}
		u64 zero = 0;
		bpf_map_update_elem(&seen, &key, &zero, 0);
	}

	struct args_t args = {};
	args.current_userns =
		(u64)BPF_CORE_READ(task, real_cred, user_ns, ns.inum);
	args.target_userns = (u64)BPF_CORE_READ(targ_ns, ns.inum);
	/*
	 * cap_effective has kernel_cap_t for type.
	 * This type definition changed along the time:
	 * 1. It was defined as a __u32 in:
	 * https://github.com/torvalds/linux/commit/1da177e4c3f4
	 * 2. It later was modified to be an array of __u32, so 64 bits kernel
	 * can use 64 bits for capabilities while supporting legacy 32 bits
	 * ones:
	 * https://github.com/torvalds/linux/commit/e338d263a76a
	 * 3. It was recently defined to be a simple u64:
	 * https://github.com/torvalds/linux/commit/f122a08b197d
	 * BPF_CORE_READ_INTO() will handle the different size for us and in any
	 * case, we define args.cap_effective as u64 which is enough to contain
	 * the information.
	 */
	BPF_CORE_READ_INTO(&args.cap_effective, task, real_cred, cap_effective);
	args.cap = cap;
	args.cap_opt = cap_opt;
	bpf_map_update_elem(&start, &pid_tgid, &args, 0);

	return 0;
}

SEC("kretprobe/cap_capable")
int BPF_KRETPROBE(ig_trace_cap_x)
{
	__u64 pid_tgid;
	__u64 uid_gid = bpf_get_current_uid_gid();
	struct args_t *ap;
	struct cap_event *event;

	pid_tgid = bpf_get_current_pid_tgid();
	ap = bpf_map_lookup_elem(&start, &pid_tgid);
	if (!ap)
		return 0; /* missed entry */

	event = gadget_reserve_buf(&events, sizeof(struct cap_event));
	if (!event)
		return 0;

	event->current_userns = ap->current_userns;
	event->target_userns = ap->target_userns;
	event->cap_effective_raw = ap->cap_effective;
	event->pid = pid_tgid;
	event->tgid = pid_tgid >> 32;
	event->cap_raw = ap->cap;
	event->uid = (u32)uid_gid;
	event->gid = (u32)(uid_gid >> 32);
	event->mntnsid = gadget_get_mntns_id();
	bpf_get_current_comm(&event->task, sizeof(event->task));
	// ret=0 means the process has the requested capability, otherwise ret=-EPERM
	event->capable = PT_REGS_RC(ctx) == 0;
	event->kstack_raw = gadget_get_kernel_stack(ctx);
	event->timestamp_raw = bpf_ktime_get_boot_ns();

	if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 1, 0)) {
		event->audit = (ap->cap_opt & CAP_OPT_NOAUDIT) == 0;
		event->insetid = (ap->cap_opt & CAP_OPT_INSETID) != 0;
	} else {
		event->audit = ap->cap_opt;
		event->insetid = -1;
	}

	struct syscall_context *sc_ctx;
	sc_ctx = bpf_map_lookup_elem(&current_syscall, &event->pid);
	if (sc_ctx) {
		event->syscall_raw = sc_ctx->nr;
	} else {
		event->syscall_raw = -1;
	}

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	bpf_map_delete_elem(&start, &pid_tgid);

	return 0;
}

/*
 * Taken from:
 * https://github.com/seccomp/libseccomp/blob/afbde6ddaec7c58c3b281d43b0b287269ffca9bd/src/syscalls.csv
 */
#if defined(__TARGET_ARCH_arm64)
#define __NR_execve 221
#define __NR_execveat 281
#define __NR_rt_sigreturn 139
#define __NR_exit_group 94
#define __NR_exit 93
#elif defined(__TARGET_ARCH_x86)
#define __NR_execve 59
#define __NR_execveat 322
#define __NR_rt_sigreturn 15
#define __NR_exit_group 231
#define __NR_exit 60
#else
#error "The trace capabilities gadget is not supported on your architecture."
#endif

static __always_inline int skip_exit_probe(int nr)
{
	return !!(nr == __NR_exit || nr == __NR_exit_group ||
		  nr == __NR_rt_sigreturn);
}

SEC("raw_tracepoint/sys_enter")
int ig_cap_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid();
	struct syscall_context sc_ctx = {};

	u64 mntns_id = gadget_get_mntns_id();

	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	u64 nr = ctx->args[1];
	sc_ctx.nr = nr;

	if (nr == __NR_execve || nr == __NR_execveat)
		gadget_enter_exec();

	// The sys_exit tracepoint is not called for some syscalls.
	if (!skip_exit_probe(nr))
		bpf_map_update_elem(&current_syscall, &pid, &sc_ctx, BPF_ANY);

	return 0;
}

SEC("raw_tracepoint/sys_exit")
int ig_cap_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid();
	struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
	long ret = ctx->args[1];

#if defined(__TARGET_ARCH_x86)
	int nr = BPF_CORE_READ(regs, orig_ax);
#elif defined(__TARGET_ARCH_arm64)
	int nr = BPF_CORE_READ(regs, syscallno);
#endif

	if (nr == __NR_execve || nr == __NR_execveat)
		pid = gadget_get_exec_caller_pid(ret);

	bpf_map_delete_elem(&current_syscall, &pid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
