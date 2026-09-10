// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/kernel_stack_map.h>
#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/user_stack_map.h>

// SELinux security contexts can be fairly long, e.g.
// system_u:system_r:container_t:s0:c123,c456
#define SCONTEXT_LEN 128
#define TCONTEXT_LEN 128
// Target class names are short, e.g. "file", "tcp_socket", "dir".
#define TCLASS_LEN 32

// The trace_event_raw_selinux_audited struct is absent from the arm64
// vmlinux.h shipped with Inspektor Gadget (that BTF was generated from a kernel
// built without CONFIG_SECURITY_SELINUX). Define it manually for arm64 so the
// gadget still compiles for that architecture. The layout matches the stable
// tracepoint format. Tracepoint context fields are read directly from the
// in-memory record, so no CO-RE relocation is performed against this struct.
#ifdef __TARGET_ARCH_arm64
struct trace_event_raw_selinux_audited {
	struct trace_entry ent;
	u32 requested;
	u32 denied;
	u32 audited;
	int result;
	u32 __data_loc_scontext;
	u32 __data_loc_tcontext;
	u32 __data_loc_tclass;
	char __data[0];
};
#endif /* __TARGET_ARCH_arm64 */

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;

	// Bitmask of the permissions that were requested.
	__u32 requested;
	// Bitmask of the permissions that were denied.
	__u32 denied;
	// Bitmask of the permissions that were audited.
	__u32 audited;
	// AVC result: 0 means allowed, non-zero (e.g. -EACCES) means denied.
	__s32 result;

	// Source security context (the context of the process).
	char scontext[SCONTEXT_LEN];
	// Target security context (the context of the object being accessed).
	char tcontext[TCONTEXT_LEN];
	// Target object class, e.g. "file", "dir", "tcp_socket".
	char tclass[TCLASS_LEN];

	gadget_kernel_stack kstack_raw;
	struct gadget_user_stack ustack;
};

// Only report AVC denials by default. Set to false to also report audited
// events that were allowed (e.g. matched by an auditallow rule).
const volatile bool denials_only = true;
GADGET_PARAM(denials_only);

// Collect the kernel stack trace that led to the AVC audit event.
const volatile bool collect_kstack = false;
GADGET_PARAM(collect_kstack);

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(selinux, events, event);

// Tracepoint __data_loc fields encode the string location as a u32: the lower
// 16 bits hold the offset from the start of the event record, the upper 16 bits
// hold the string length.
static __always_inline char *data_loc_ptr(void *ctx, __u32 data_loc)
{
	return (char *)ctx + (data_loc & 0xffff);
}

SEC("tracepoint/avc/selinux_audited")
int ig_selinux(struct trace_event_raw_selinux_audited *ctx)
{
	struct event *event;

	if (denials_only && ctx->denied == 0)
		return 0;

	if (gadget_should_discard_data_current())
		return 0;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	/* Ring-buffer reservations are not guaranteed to be zero-filled. */
	__builtin_memset(event, 0, sizeof(*event));
	gadget_process_populate(&event->proc);
	event->timestamp_raw = bpf_ktime_get_boot_ns();

	event->requested = ctx->requested;
	event->denied = ctx->denied;
	event->audited = ctx->audited;
	event->result = ctx->result;

	bpf_probe_read_kernel_str(event->scontext, sizeof(event->scontext),
				  data_loc_ptr(ctx, ctx->__data_loc_scontext));
	bpf_probe_read_kernel_str(event->tcontext, sizeof(event->tcontext),
				  data_loc_ptr(ctx, ctx->__data_loc_tcontext));
	bpf_probe_read_kernel_str(event->tclass, sizeof(event->tclass),
				  data_loc_ptr(ctx, ctx->__data_loc_tclass));

	if (collect_kstack)
		event->kstack_raw = gadget_get_kernel_stack(ctx);

	gadget_get_user_stack_from_tracepoint(ctx, &event->ustack);

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
