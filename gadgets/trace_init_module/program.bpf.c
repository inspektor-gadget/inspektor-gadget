// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 The Inspektor Gadget authors

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/filesystem.h>
#include <gadget/macros.h>
#include <gadget/types.h>

#define PARAM_VALUES_MAX 256

enum syscall_type {
	init_module,
	finit_module,
};

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;

	// Common fields
	enum syscall_type syscall_raw;
	char param_values[PARAM_VALUES_MAX];

	// init_module specific
	__u64 len;

	// finit_module specific
	__s32 fd;
	__u32 flags;
	char filepath[GADGET_PATH_MAX];
};

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(init, events, event);

SEC("tracepoint/syscalls/sys_enter_init_module")
int ig_init_module_e(struct syscall_trace_enter *ctx)
{
	struct event *event;
	__u64 len = (__u64)ctx->args[1];
	const char *param_values = (const char *)ctx->args[2];

	if (gadget_should_discard_data_current())
		return 0;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	gadget_process_populate(&event->proc);
	event->timestamp_raw = bpf_ktime_get_boot_ns();

	event->syscall_raw = init_module;

	event->len = len;
	event->fd = 0;
	event->flags = 0;
	event->filepath[0] = '\0';

	if (param_values)
		bpf_probe_read_user_str(event->param_values,
					sizeof(event->param_values),
					param_values);
	else
		event->param_values[0] = '\0';

	gadget_submit_buf(ctx, &events, event, sizeof(*event));
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int ig_finit_module_e(struct syscall_trace_enter *ctx)
{
	struct event *event;
	__s32 fd = (__s32)ctx->args[0];
	const char *param_values = (const char *)ctx->args[1];
	__u32 flags = (__u32)ctx->args[2];

	if (gadget_should_discard_data_current())
		return 0;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	gadget_process_populate(&event->proc);
	event->timestamp_raw = bpf_ktime_get_boot_ns();

	event->syscall_raw = finit_module;

	event->fd = fd;
	event->flags = flags;
	event->len = 0;

	// Try to resolve fd to filepath
	// Only returns a path when fd points to a file in the kernel filesystem.
	// When fd points to memory (e.g., memfd), this is not yet handled and
	// filepath will be set to empty string.
	if (fd >= 0) {
		long r = read_full_path_of_open_file_fd(
			fd, event->filepath, sizeof(event->filepath));
		if (r <= 0)
			event->filepath[0] = '\0';
	} else {
		event->filepath[0] = '\0';
	}

	if (param_values)
		bpf_probe_read_user_str(event->param_values,
					sizeof(event->param_values),
					param_values);
	else
		event->param_values[0] = '\0';

	gadget_submit_buf(ctx, &events, event, sizeof(*event));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
