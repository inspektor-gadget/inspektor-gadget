// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 The Inspektor Gadget authors

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/filesystem.h>

/*
 * Emits one event per successful rename(2), renameat(2) or renameat2(2).
 *
 * - sys_enter_*: save the name pointers and flags in `start`, keyed by tid.
 *   arm64 has no rename(2), only renameat(2) and renameat2(2).
 * - security_path_rename (only attached with --paths, see go/program.go):
 *   resolve the absolute old and new paths into the same `start` entry.
 * - sys_exit_*: emit the event if the syscall returned 0.
 */

enum rename_flags_set : u32 {
	RENAME_NOREPLACE = 1 << 0,
	RENAME_EXCHANGE = 1 << 1,
	RENAME_WHITEOUT = 1 << 2,
};

struct args_t {
	const char *oldname;
	const char *newname;
	__u32 flags;
	char oldpath[GADGET_PATH_MAX];
	char newpath[GADGET_PATH_MAX];
};

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;

	enum rename_flags_set flags_raw;
	char oldname[GADGET_PATH_MAX];
	char newname[GADGET_PATH_MAX];
	char oldpath[GADGET_PATH_MAX];
	char newpath[GADGET_PATH_MAX];
};

/* struct args_t is too big for the BPF stack: build it here first. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct args_t);
} args_scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, struct args_t);
} start SEC(".maps");

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(rename, events, event);

static __always_inline int trace_enter(const char *oldname, const char *newname,
				       __u32 flags)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u32 zero = 0;
	struct args_t *args;

	if (gadget_should_discard_data_current()) {
		/*
		 * Drop any entry leaked for this tid by a rename that never
		 * reached the exit tracepoint, so it can't be reported for a
		 * task the filter discards.
		 */
		bpf_map_delete_elem(&start, &tid);
		return 0;
	}

	args = bpf_map_lookup_elem(&args_scratch, &zero);
	if (!args)
		return 0;

	args->oldname = oldname;
	args->newname = newname;
	args->flags = flags;
	args->oldpath[0] = '\0';
	args->newpath[0] = '\0';
	bpf_map_update_elem(&start, &tid, args, BPF_ANY);

	return 0;
}

#ifndef __TARGET_ARCH_arm64
SEC("tracepoint/syscalls/sys_enter_rename")
int ig_rename_e(struct syscall_trace_enter *ctx)
{
	return trace_enter((const char *)ctx->args[0],
			   (const char *)ctx->args[1], 0);
}
#endif /* !__TARGET_ARCH_arm64 */

SEC("tracepoint/syscalls/sys_enter_renameat")
int ig_renameat_e(struct syscall_trace_enter *ctx)
{
	return trace_enter((const char *)ctx->args[1],
			   (const char *)ctx->args[3], 0);
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int ig_renameat2_e(struct syscall_trace_enter *ctx)
{
	return trace_enter((const char *)ctx->args[1],
			   (const char *)ctx->args[3], (__u32)ctx->args[4]);
}

SEC("kprobe/security_path_rename")
int BPF_KPROBE(ig_rename_paths, const struct path *old_dir,
	       struct dentry *old_dentry, const struct path *new_dir,
	       struct dentry *new_dentry)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct args_t *args;
	struct path p;
	char *s;

	/* Only renames that passed the filters in trace_enter() */
	args = bpf_map_lookup_elem(&start, &tid);
	if (!args)
		return 0;

	/*
	 * get_path_str() returns a pointer into a per-CPU scratch buffer that the
	 * next call overwrites: copy each result before resolving the next one.
	 */
	p.dentry = old_dentry;
	p.mnt = BPF_CORE_READ(old_dir, mnt);
	s = get_path_str(&p);
	if (!s || bpf_probe_read_kernel_str(args->oldpath,
					    sizeof(args->oldpath), s) < 0)
		args->oldpath[0] = '\0';

	p.dentry = new_dentry;
	p.mnt = BPF_CORE_READ(new_dir, mnt);
	s = get_path_str(&p);
	if (!s || bpf_probe_read_kernel_str(args->newpath,
					    sizeof(args->newpath), s) < 0)
		args->newpath[0] = '\0';

	return 0;
}

static __always_inline int trace_exit(struct syscall_trace_exit *ctx)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct args_t *args;
	struct event *event;

	args = bpf_map_lookup_elem(&start, &tid);
	if (!args)
		return 0; /* missed entry or filtered out */

	if (ctx->ret != 0)
		goto cleanup; /* only successful renames */

	/* Never report a task the filter discards, even with a stale entry */
	if (gadget_should_discard_data_current())
		goto cleanup;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		goto cleanup;

	gadget_process_populate(&event->proc);
	event->timestamp_raw = bpf_ktime_get_boot_ns();
	event->flags_raw = args->flags;

	if (bpf_probe_read_user_str(event->oldname, sizeof(event->oldname),
				    args->oldname) < 0)
		event->oldname[0] = '\0';
	if (bpf_probe_read_user_str(event->newname, sizeof(event->newname),
				    args->newname) < 0)
		event->newname[0] = '\0';
	if (bpf_probe_read_kernel_str(event->oldpath, sizeof(event->oldpath),
				      args->oldpath) < 0)
		event->oldpath[0] = '\0';
	if (bpf_probe_read_kernel_str(event->newpath, sizeof(event->newpath),
				      args->newpath) < 0)
		event->newpath[0] = '\0';

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

cleanup:
	bpf_map_delete_elem(&start, &tid);
	return 0;
}

#ifndef __TARGET_ARCH_arm64
SEC("tracepoint/syscalls/sys_exit_rename")
int ig_rename_x(struct syscall_trace_exit *ctx)
{
	return trace_exit(ctx);
}
#endif /* !__TARGET_ARCH_arm64 */

SEC("tracepoint/syscalls/sys_exit_renameat")
int ig_renameat_x(struct syscall_trace_exit *ctx)
{
	return trace_exit(ctx);
}

SEC("tracepoint/syscalls/sys_exit_renameat2")
int ig_renameat2_x(struct syscall_trace_exit *ctx)
{
	return trace_exit(ctx);
}

char LICENSE[] SEC("license") = "GPL";
