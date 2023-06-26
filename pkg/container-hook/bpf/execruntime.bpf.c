// SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0
#include <vmlinux/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "execruntime.h"

const volatile int max_args = DEFAULT_MAXARGS;

static const struct record empty_record = {};

// configured by userspace
const volatile u64 tracer_group = 0;

// ig_fa_pick_ctx keeps context for kprobe/kretprobe fsnotify_remove_first_event
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, u64); // tgid_pid
	__type(value, u64); // dummy
} ig_fa_pick_ctx SEC(".maps");

// ig_fa_records is consumed by userspace
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 64);
	__type(value, struct record);
} ig_fa_records SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, u32); // tgid (fanotify will need to lookup by tgid)
	__type(value, struct record);
} exec_args SEC(".maps");

SEC("kprobe/fsnotify_remove_first_event")
int BPF_KPROBE(ig_fa_pick_e, struct fsnotify_group *group)
{
	u64 current_pid_tgid;
	u64 dummy = 0;

	if (tracer_group != (u64)group)
		return 0;

	current_pid_tgid = bpf_get_current_pid_tgid();

	// Keep context for kretprobe/fsnotify_remove_first_event
	bpf_map_update_elem(&ig_fa_pick_ctx, &current_pid_tgid, &dummy, 0);

	return 0;
}

SEC("kretprobe/fsnotify_remove_first_event")
int BPF_KRETPROBE(ig_fa_pick_x, struct fanotify_event *ret)
{
	struct record *record;
	u64 current_pid_tgid;
	u32 event_tgid;
	u64 *exists;

	// current_pid_tgid is the Inspektor Gadget task
	current_pid_tgid = bpf_get_current_pid_tgid();

	exists = bpf_map_lookup_elem(&ig_fa_pick_ctx, &current_pid_tgid);
	if (!exists)
		return 0;

	// event_tgid is the tgid of the process that triggered the fanotify event.
	// Since Inspektor Gadget didn't use FAN_REPORT_TID, this is the process id
	// and not the thread id.
	event_tgid = BPF_CORE_READ(ret, pid, numbers[0].nr);

	record = bpf_map_lookup_elem(&exec_args, &event_tgid);
	if (!record) {
		// no record found but we need to push an empty record in the queue to
		// ensure userspace understands that there is no record for this event
		bpf_map_push_elem(&ig_fa_records, &empty_record, 0);
		bpf_map_delete_elem(&ig_fa_pick_ctx, &current_pid_tgid);
		return 0;
	}

	bpf_map_push_elem(&ig_fa_records, record, 0);
	bpf_map_delete_elem(&ig_fa_pick_ctx, &current_pid_tgid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int ig_execve_e(struct trace_event_raw_sys_enter* ctx)
{
	u64 pid_tgid;
	u32 tgid;
	struct record *record;
	struct task_struct *task;
	uid_t uid = (u32)bpf_get_current_uid_gid();

	int ret;
	const char **args = (const char **)(ctx->args[1]);
	const char *argp;
	int i;

	pid_tgid = bpf_get_current_pid_tgid();
	tgid = pid_tgid >> 32;

	// Add new entry but not from the stack due to size limitations
	if (bpf_map_update_elem(&exec_args, &tgid, &empty_record, 0))
		return 0;
	record = bpf_map_lookup_elem(&exec_args, &tgid);
	if (!record)
		return 0;

	task = (struct task_struct*)bpf_get_current_task();

	bpf_get_current_comm(&record->caller_comm, sizeof(record->caller_comm));
	record->pid = tgid;
	record->args_size = 0;

	ret = bpf_probe_read_user_str(record->args, ARGSIZE, (const char*)ctx->args[0]);
	if (ret > 0 && ret <= ARGSIZE) {
		record->args_size += ret;
	} else {
		// write an empty string
		record->args[0] = '\0';
		record->args_size++;
	}

	#pragma unroll
	for (i = 1; i < TOTAL_MAX_ARGS && i < max_args; i++) {
		ret = bpf_probe_read_user(&argp, sizeof(argp), &args[i]);
		if (ret != 0 || !argp)
			return 0;

		if (record->args_size > LAST_ARG)
			return 0;

		ret = bpf_probe_read_user_str(&record->args[record->args_size], ARGSIZE, argp);
		if (ret > 0 && ret <= ARGSIZE) {
			record->args_size += ret;
		} else {
			return 0;
		}
	}

	return 0;
}

#ifdef __TARGET_ARCH_arm64
SEC("kretprobe/do_execveat_common.isra.0")
int BPF_KRETPROBE(ig_execve_x)
#else /* !__TARGET_ARCH_arm64 */
SEC("tracepoint/syscalls/sys_exit_execve")
int ig_execve_x(struct trace_event_raw_sys_exit* ctx)
#endif /* !__TARGET_ARCH_arm64 */
{
	u64 pid_tgid;
	u32 tgid;

	pid_tgid = bpf_get_current_pid_tgid();
	tgid = (u32)pid_tgid;

	bpf_map_delete_elem(&exec_args, &tgid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
