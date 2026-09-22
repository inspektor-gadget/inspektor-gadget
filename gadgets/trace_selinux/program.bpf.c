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
// gadget still compiles for that architecture.
//
// Apply preserve_access_index the same way vmlinux.h does for the structs it
// defines, so that field accesses are CO-RE relocated against the BTF of the
// running kernel rather than using the offsets hardcoded below. Without this,
// arm64 would be the only architecture reading this tracepoint at fixed
// offsets, since amd64 gets the struct from vmlinux.h and is already relocated.
#ifdef __TARGET_ARCH_arm64
#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push(__attribute__((preserve_access_index)), \
			     apply_to = record)
#endif

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

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif
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

// OTel symbolization of user stacks is driven by a bpf_tail_call into the OTel
// unwinder, which only accepts a BPF_PROG_TYPE_KPROBE context. A tracepoint
// program cannot satisfy that, so the user stack is instead collected by a
// kprobe on avc_audit_post_callback(), the kernel function that calls the
// selinux_audited tracepoint. The kprobe stores the stack here and the
// tracepoint below picks it up when it builds the event.
//
// The handoff is keyed by thread id rather than being per-CPU: slow_avc_audit()
// runs under rcu_read_lock() and, on PREEMPT_RCU kernels, the thread can be
// preempted and migrated to another CPU between the kprobe and the tracepoint.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct gadget_user_stack);
} ig_selinux_ustacks SEC(".maps");

// Tracepoint __data_loc fields encode the string location as a u32: the lower
// 16 bits hold the offset from the start of the event record, the upper 16 bits
// hold the string length.
static __always_inline char *data_loc_ptr(void *ctx, __u32 data_loc)
{
	return (char *)ctx + (data_loc & 0xffff);
}

// avc_audit_post_callback() calls the selinux_audited tracepoint
// unconditionally, so this kprobe is always followed by ig_selinux() below, on
// the same thread. That is what makes the handoff safe: an entry stored here is
// always consumed by the next selinux_audited event of this thread.
//
// Hooking slow_avc_audit() instead would not give that guarantee, as it reaches
// the tracepoint through common_lsm_audit(), which returns early when
// audit_log_start() fails. That would leave stale stacks behind to be picked up
// by a later, unrelated event.
SEC("kprobe/avc_audit_post_callback")
int ig_selinux_ustack(struct pt_regs *ctx)
{
	struct gadget_user_stack ustack;
	__u32 tid;

	if (!collect_ustack || !collect_otel_stack)
		return 0;

	if (gadget_should_discard_data_current())
		return 0;

	__builtin_memset(&ustack, 0, sizeof(ustack));
	gadget_get_user_stack_from_kprobe(ctx, &ustack);

	tid = (__u32)bpf_get_current_pid_tgid();
	bpf_map_update_elem(&ig_selinux_ustacks, &tid, &ustack, BPF_ANY);

	return 0;
}

SEC("tracepoint/avc/selinux_audited")
int ig_selinux(struct trace_event_raw_selinux_audited *ctx)
{
	struct gadget_user_stack ustack;
	struct event *event;
	__u32 tid;

	__builtin_memset(&ustack, 0, sizeof(ustack));

	// Drain the stack collected by the kprobe before any early return below,
	// so that a filtered-out event never leaves an entry behind for a later
	// event to pick up.
	if (collect_ustack && collect_otel_stack) {
		struct gadget_user_stack *pending;

		tid = (__u32)bpf_get_current_pid_tgid();
		pending = bpf_map_lookup_elem(&ig_selinux_ustacks, &tid);
		if (pending) {
			ustack = *pending;
			bpf_map_delete_elem(&ig_selinux_ustacks, &tid);
		}
	}

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

	if (collect_ustack && collect_otel_stack)
		event->ustack = ustack;
	else
		gadget_get_user_stack_from_tracepoint(ctx, &event->ustack);

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
