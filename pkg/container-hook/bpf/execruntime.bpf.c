// SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "execruntime.h"

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
	__uint(max_entries, 128);
	__type(key, u32); // pid (not tgid)
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
	u32 event_pid;
	u64 *exists;

	// current_pid_tgid is the Inspektor Gadget task
	current_pid_tgid = bpf_get_current_pid_tgid();

	exists = bpf_map_lookup_elem(&ig_fa_pick_ctx, &current_pid_tgid);
	if (!exists)
		return 0;

	// event_pid is the thread that triggered the fanotify event.
	// Since Inspektor Gadget uses FAN_REPORT_TID, this is the thread id
	// and not the process id.
	event_pid = BPF_CORE_READ(ret, pid, numbers[0].nr);

	record = bpf_map_lookup_elem(&exec_args, &event_pid);
	if (!record) {
		// no record found but we need to push an empty record in the queue to
		// ensure userspace understands that there is no record for this event
		goto fail;
	}

	bpf_map_push_elem(&ig_fa_records, record, 0);
	bpf_map_delete_elem(&ig_fa_pick_ctx, &current_pid_tgid);
	return 0;

fail:
	bpf_map_push_elem(&ig_fa_records, &empty_record, 0);
	bpf_map_delete_elem(&ig_fa_pick_ctx, &current_pid_tgid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int ig_execve_e(struct syscall_trace_enter *ctx)
{
	u64 pid_tgid;
	u32 tgid, pid;
	struct record *record;
	struct task_struct *task;
	uid_t uid = (u32)bpf_get_current_uid_gid();
	u64 *pid_sum;

	int ret;
	const char **args = (const char **)(ctx->args[1]);
	const char *argp;
	int i;

	pid_tgid = bpf_get_current_pid_tgid();
	tgid = pid_tgid >> 32;
	pid = (u32)pid_tgid;

	// Add new entry but not from the stack due to size limitations
	if (bpf_map_update_elem(&exec_args, &pid, &empty_record, 0))
		return 0;
	record = bpf_map_lookup_elem(&exec_args, &pid);
	if (!record)
		return 0;

	task = (struct task_struct *)bpf_get_current_task();

	bpf_get_current_comm(&record->caller_comm, sizeof(record->caller_comm));
	record->mntns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	record->pid = tgid;
	record->args_size = 0;

	ret = bpf_probe_read_user_str(record->args, ARGSIZE,
				      (const char *)ctx->args[0]);
	if (ret > 0 && ret <= ARGSIZE) {
		record->args_size += ret;
	} else {
		// write an empty string
		record->args[0] = '\0';
		record->args_size++;
	}

#pragma unroll
	for (i = 1; i < TOTAL_MAX_ARGS; i++) {
		ret = bpf_probe_read_user(&argp, sizeof(argp), &args[i]);
		if (ret != 0 || !argp)
			return 0;

		if (record->args_size > LAST_ARG)
			return 0;

		ret = bpf_probe_read_user_str(&record->args[record->args_size],
					      ARGSIZE, argp);
		if (ret > 0 && ret <= ARGSIZE) {
			record->args_size += ret;
		} else {
			return 0;
		}
	}

	return 0;
}

// tracepoint/sched/sched_process_exec is called after a successful execve
SEC("tracepoint/sched/sched_process_exec")
int ig_sched_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	// Don't use the pid from bpf_get_current_pid_tgid() as a key: the pid
	// might have changed since sys_enter_execve if the execve was performed by
	// a thread. Thankfully, the old thread id is passed in ctx->old_pid.
	u32 execs_lookup_key = ctx->old_pid;
	bpf_map_delete_elem(&exec_args, &execs_lookup_key);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int ig_execve_x(struct syscall_trace_exit *ctx)
{
	// - If the execve was successful, ig_sched_exec would have deleted the
	//   entry already. Deleting it again is harmless.
	// - If the execve failed, we need to delete the entry here.
	//   bpf_get_current_pid_tgid() returns the same pid as in
	//   sys_enter_execve.
	// - If the execve was blocked by seccomp, sys_enter_execve was not called.
	//   But deleting the entry that was not added is harmless.
	// - We cannot reliably distinguish successful execve from failed execve
	//   with ctx->ret because it can be changed by seccomp with
	//   SCMP_ACT_ERRNO(0).
	u32 pid = (u32)bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&exec_args, &pid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
