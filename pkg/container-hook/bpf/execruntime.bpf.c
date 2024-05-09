// SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0
#include <vmlinux.h>
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
	__type(key, u32); // pid (not tgid)
	__type(value, struct record);
} exec_args SEC(".maps");

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
// So we can insert a tgid->pid mapping in the same hash entry by adding
// the pid in value and removing it by subtracting. By the time we need to
// lookup the pid by the tgid, there will be only one pid left in the hash entry.
struct pid_set {
	__u64 pid_sum;
	__u64 pid_count;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t); // tgid
	__type(value, struct pid_set);
	__uint(max_entries, 1024);
} pid_by_tgid SEC(".maps");

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
	u32 pid;
	u64 *exists;
	struct pid_set *pid_set;

	// current_pid_tgid is the Inspektor Gadget task
	current_pid_tgid = bpf_get_current_pid_tgid();

	exists = bpf_map_lookup_elem(&ig_fa_pick_ctx, &current_pid_tgid);
	if (!exists)
		return 0;

	// event_tgid is the tgid of the process that triggered the fanotify event.
	// Since Inspektor Gadget didn't use FAN_REPORT_TID, this is the process id
	// and not the thread id.
	event_tgid = BPF_CORE_READ(ret, pid, numbers[0].nr);

	pid_set = bpf_map_lookup_elem(&pid_by_tgid, &event_tgid);
	if (!pid_set)
		goto fail;

	if (pid_set->pid_count != 1)
		goto fail;
	pid = pid_set->pid_sum;

	record = bpf_map_lookup_elem(&exec_args, &pid);
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
	struct pid_set zero_pid_set = { 0, 0 };
	struct pid_set *pid_set;
	u64 *pid_sum;

	int ret;
	const char **args = (const char **)(ctx->args[1]);
	const char *argp;
	int i;

	pid_tgid = bpf_get_current_pid_tgid();
	tgid = pid_tgid >> 32;
	pid = (u32)pid_tgid;

	bpf_map_update_elem(&pid_by_tgid, &tgid, &zero_pid_set, BPF_NOEXIST);

	pid_set = bpf_map_lookup_elem(&pid_by_tgid, &tgid);
	if (!pid_set)
		return 0;

	__atomic_add_fetch(&pid_set->pid_sum, (u64)pid, __ATOMIC_RELAXED);
	__atomic_add_fetch(&pid_set->pid_count, 1, __ATOMIC_RELAXED);

	// Add new entry but not from the stack due to size limitations
	if (bpf_map_update_elem(&exec_args, &pid, &empty_record, 0))
		return 0;
	record = bpf_map_lookup_elem(&exec_args, &pid);
	if (!record)
		return 0;

	task = (struct task_struct *)bpf_get_current_task();

	bpf_get_current_comm(&record->caller_comm, sizeof(record->caller_comm));
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
	for (i = 1; i < TOTAL_MAX_ARGS && i < max_args; i++) {
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

SEC("tracepoint/syscalls/sys_exit_execve")
int ig_execve_x(struct syscall_trace_exit *ctx)
{
	u64 pid_tgid;
	u32 tgid, pid;
	u32 execs_lookup_key;
	int ret;
	struct pid_set *pid_set;

	pid_tgid = bpf_get_current_pid_tgid();
	tgid = pid_tgid >> 32;
	pid = (u32)pid_tgid;
	ret = ctx->ret;

	pid_set = bpf_map_lookup_elem(&pid_by_tgid, &tgid);
	if (!pid_set)
		return 0;

	// sys_enter_execve and sys_exit_execve might be called from different
	// threads. We need to lookup the pid from the tgid.
	execs_lookup_key = (ret == 0) ? pid_set->pid_sum : pid;
	bpf_map_delete_elem(&exec_args, &execs_lookup_key);

	// Remove the tgid->pid mapping if the value reaches 0
	// or the execve() call was successful
	// Convert pid to u64 before applying the negative sign to ensure it's not
	// truncated
	__atomic_add_fetch(&pid_set->pid_sum, -((u64)pid), __ATOMIC_RELAXED);
	__atomic_add_fetch(&pid_set->pid_count, -1ULL, __ATOMIC_RELAXED);
	if (pid_set->pid_sum == 0 || ret == 0)
		bpf_map_delete_elem(&pid_by_tgid, &tgid);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
