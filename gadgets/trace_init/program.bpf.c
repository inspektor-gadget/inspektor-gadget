// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 The Inspektor Gadget authors

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/types.h>

#define PARAM_VALUES_MAX 256

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;
	__u64 len;
	char param_values[PARAM_VALUES_MAX];
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
	event->len = len;
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
