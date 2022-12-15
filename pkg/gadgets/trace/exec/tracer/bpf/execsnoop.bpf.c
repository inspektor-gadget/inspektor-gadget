// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <vmlinux/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#ifdef __TARGET_ARCH_arm64
#include <bpf/bpf_tracing.h>
#endif /* __TARGET_ARCH_arm64 */
#include "execsnoop.h"

const volatile bool ignore_failed = true;
const volatile uid_t targ_uid = INVALID_UID;
const volatile int max_args = DEFAULT_MAXARGS;
const volatile bool filter_by_mnt_ns = false;

static const struct event empty_event = {};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, pid_t);
	__type(value, struct event);
} execs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(u32));
} mount_ns_filter SEC(".maps");

static __always_inline bool valid_uid(uid_t uid) {
	return uid != INVALID_UID;
}

#ifdef __TARGET_ARCH_arm64
SEC("kprobe/do_execveat_common.isra.0")
int BPF_KPROBE(ig_execveat_e)
#else /* !__TARGET_ARCH_arm64 */
SEC("tracepoint/syscalls/sys_enter_execve")
int ig_execve_e(struct trace_event_raw_sys_enter* ctx)
#endif /* !__TARGET_ARCH_arm64 */
{
	u64 id;
	pid_t pid, tgid;
	struct event *event;
	struct task_struct *task;
	uid_t uid = (u32)bpf_get_current_uid_gid();
#ifndef __TARGET_ARCH_arm64
	unsigned int ret;
	const char **args = (const char **)(ctx->args[1]);
	const char *argp;
	int i;
#endif /* !__TARGET_ARCH_arm64 */
	u64 mntns_id;

	if (valid_uid(targ_uid) && targ_uid != uid)
		return 0;

	task = (struct task_struct*)bpf_get_current_task();
	mntns_id = (u64) BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

	if (filter_by_mnt_ns && !bpf_map_lookup_elem(&mount_ns_filter, &mntns_id))
		return 0;

	id = bpf_get_current_pid_tgid();
	pid = (pid_t)id;
	tgid = id >> 32;
	if (bpf_map_update_elem(&execs, &pid, &empty_event, BPF_NOEXIST))
		return 0;

	event = bpf_map_lookup_elem(&execs, &pid);
	if (!event)
		return 0;

	event->timestamp = bpf_ktime_get_boot_ns();
	event->pid = tgid;
	event->uid = uid;
	event->ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
	event->args_count = 0;
	event->args_size = 0;
	event->mntns_id = mntns_id;

#ifndef __TARGET_ARCH_arm64
	ret = bpf_probe_read_user_str(event->args, ARGSIZE, (const char*)ctx->args[0]);
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

		ret = bpf_probe_read_user_str(&event->args[event->args_size], ARGSIZE, argp);
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
#else /* __TARGET_ARCH_arm64 */
	const char not_supported[] = "args are not supported on arm64";
	__builtin_memcpy(event->args, not_supported, sizeof(not_supported));
#endif /* __TARGET_ARCH_arm64 */
	return 0;
}

#ifdef __TARGET_ARCH_arm64
SEC("kretprobe/do_execveat_common.isra.0")
int BPF_KRETPROBE(ig_execveat_x)
#else /* !__TARGET_ARCH_arm64 */
SEC("tracepoint/syscalls/sys_exit_execve")
int ig_execve_x(struct trace_event_raw_sys_exit* ctx)
#endif /* !__TARGET_ARCH_arm64 */
{
	u64 id;
	pid_t pid;
	int ret;
	struct event *event;
	u32 uid = (u32)bpf_get_current_uid_gid();

	if (valid_uid(targ_uid) && targ_uid != uid)
		return 0;
	id = bpf_get_current_pid_tgid();
	pid = (pid_t)id;
	event = bpf_map_lookup_elem(&execs, &pid);
	if (!event)
		return 0;
#ifdef __TARGET_ARCH_arm64
	ret = PT_REGS_RC(ctx);
#else /* !__TARGET_ARCH_arm64 */
	ret = ctx->ret;
#endif /* !__TARGET_ARCH_arm64 */
	if (ignore_failed && ret < 0)
		goto cleanup;

	event->retval = ret;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	size_t len = EVENT_SIZE(event);
	if (len <= sizeof(*event))
		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, len);
cleanup:
	bpf_map_delete_elem(&execs, &pid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
