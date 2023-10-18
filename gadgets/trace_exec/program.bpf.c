// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#ifdef __TARGET_ARCH_arm64
#include <bpf/bpf_tracing.h>
#endif /* __TARGET_ARCH_arm64 */

#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#define ARGSIZE 128
#define TOTAL_MAX_ARGS 60
#define DEFAULT_MAXARGS 20
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)
#define INVALID_UID ((uid_t)-1)
#define BASE_EVENT_SIZE (size_t)(&((struct event *)0)->args)
#define EVENT_SIZE(e) (BASE_EVENT_SIZE + e->args_size)
#define LAST_ARG (FULL_MAX_ARGS_ARR - ARGSIZE)

struct event {
	mnt_ns_id_t mntns_id;
	__u64 timestamp;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
	__u32 loginuid;
	__u32 sessionid;
	int retval;
	int args_count;
	unsigned int args_size;
	__u8 comm[TASK_COMM_LEN];
	__u8 args[FULL_MAX_ARGS_ARR];
};

const volatile bool ignore_failed = true;
const volatile uid_t targ_uid = INVALID_UID;
const volatile int max_args = DEFAULT_MAXARGS;

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
	//__uint(value_size, sizeof(u32));
	__type(value, struct event);
} events SEC(".maps");

GADGET_TRACE_MAP(events);

static __always_inline bool valid_uid(uid_t uid)
{
	return uid != INVALID_UID;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int ig_execve_e(struct trace_event_raw_sys_enter *ctx)
{
	u64 id;
	pid_t pid, tgid;
	struct event *event;
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

	event->timestamp = bpf_ktime_get_boot_ns();
	event->pid = tgid;
	event->uid = uid;
	event->gid = gid;
	event->loginuid = BPF_CORE_READ(task, loginuid.val);
	event->sessionid = BPF_CORE_READ(task, sessionid);
	event->ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
	event->args_count = 0;
	event->args_size = 0;
	event->mntns_id = mntns_id;

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

#ifdef __TARGET_ARCH_arm64
SEC("kretprobe/do_execveat_common.isra.0")
int BPF_KRETPROBE(ig_execveat_x)
#else /* !__TARGET_ARCH_arm64 */
SEC("tracepoint/syscalls/sys_exit_execve")
int ig_execve_x(struct trace_event_raw_sys_exit *ctx)
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
		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
				      len);
cleanup:
	bpf_map_delete_elem(&execs, &pid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
