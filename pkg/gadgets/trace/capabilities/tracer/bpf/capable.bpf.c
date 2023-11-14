// SPDX-License-Identifier: GPL-2.0
//
// Unique filtering based on
// https://github.com/libbpf/libbpf-rs/tree/master/examples/capable
//
// Copyright 2022 Sony Group Corporation

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "capable.h"
#include <gadget/mntns_filter.h>

// include/linux/security.h
#ifndef CAP_OPT_NOAUDIT
#define CAP_OPT_NOAUDIT 1 << 1
#endif

#define MAX_ENTRIES 10240

const volatile pid_t my_pid = -1;
const volatile pid_t targ_pid = -1;
const volatile u32 linux_version_code = 0;
const volatile bool audit_only = false;
const volatile bool unique = false;

extern int LINUX_KERNEL_VERSION __kconfig;

// we need this to make sure the compiler doesn't remove our struct
const struct cap_event *unusedcapevent __attribute__((unused));

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

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

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
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(struct syscall_context));
	__uint(max_entries,
	       1048576); // There can be many threads sleeping in some futex/poll syscalls
} current_syscall SEC(".maps");

SEC("kprobe/cap_capable")
int BPF_KPROBE(ig_trace_cap_e, const struct cred *cred,
	       struct user_namespace *targ_ns, int cap, int cap_opt)
{
	__u32 pid;
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
	pid = pid_tgid >> 32;

	if (pid == my_pid)
		return 0;

	if (targ_pid != -1 && targ_pid != pid)
		return 0;

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
	int ret;

	pid_tgid = bpf_get_current_pid_tgid();
	ap = bpf_map_lookup_elem(&start, &pid_tgid);
	if (!ap)
		return 0; /* missed entry */

	struct cap_event event = {};
	event.current_userns = ap->current_userns;
	event.target_userns = ap->target_userns;
	event.cap_effective = ap->cap_effective;
	event.pid = pid_tgid >> 32;
	event.tgid = pid_tgid;
	event.cap = ap->cap;
	event.uid = (u32)uid_gid;
	event.gid = (u32)(uid_gid >> 32);
	event.mntnsid = gadget_get_mntns_id();
	bpf_get_current_comm(&event.task, sizeof(event.task));
	event.ret = PT_REGS_RC(ctx);
	event.timestamp = bpf_ktime_get_boot_ns();

	if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 1, 0)) {
		event.audit = (ap->cap_opt & CAP_OPT_NOAUDIT) == 0;
		event.insetid = (ap->cap_opt & CAP_OPT_INSETID) != 0;
	} else {
		event.audit = ap->cap_opt;
		event.insetid = -1;
	}

	struct syscall_context *sc_ctx;
	sc_ctx = bpf_map_lookup_elem(&current_syscall, &pid_tgid);
	if (sc_ctx) {
		event.syscall = sc_ctx->nr;
	} else {
		event.syscall = -1;
	}

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
			      sizeof(event));

	bpf_map_delete_elem(&start, &pid_tgid);

	return 0;
}

/*
 * Taken from:
 * https://github.com/seccomp/libseccomp/blob/afbde6ddaec7c58c3b281d43b0b287269ffca9bd/src/syscalls.csv
 */
#if defined(__TARGET_ARCH_arm64)
#define __NR_rt_sigreturn 139
#define __NR_exit_group 94
#define __NR_exit 93
#elif defined(__TARGET_ARCH_x86)
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
	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pt_regs regs = {};
	struct syscall_context sc_ctx = {};

	u64 mntns_id = gadget_get_mntns_id();

	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	u64 nr = ctx->args[1];
	sc_ctx.nr = nr;

	// The sys_exit tracepoint is not called for some syscalls.
	if (!skip_exit_probe(nr))
		bpf_map_update_elem(&current_syscall, &pid_tgid, &sc_ctx,
				    BPF_ANY);

	return 0;
}

SEC("raw_tracepoint/sys_exit")
int ig_cap_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&current_syscall, &pid_tgid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
