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

// The kernel keeps the permission names of every object class in a static
// const array, secclass_map[], indexed by tclass-1. It is not reachable through
// BTF: being a plain const table that the kernel only ever reads, it has no
// BTF_KIND_VAR, and nothing in the kernel retains a pointer to it. The only way
// to reach it is by address.
//
// An untyped ksym makes the loader patch the address from kallsyms into the
// instruction before load. Taking its address is the only legal use.
extern void secclass_map __ksym;

// CO-RE flavors: the "___ig" suffix is stripped when matching against the BTF
// of the running kernel, so these relocate by field name and need not list the
// members that precede the ones used here.
//
// Flavors are needed because the arm64 vmlinux.h shipped with Inspektor Gadget
// comes from a kernel built without CONFIG_SECURITY_SELINUX: it lacks
// security_class_mapping and selinux_audit_data entirely, and it does define
// common_audit_data but with an empty LSM union, which cannot be redeclared.
struct security_class_mapping___ig {
	const char *name;
	const char *perms[33];
} __attribute__((preserve_access_index));

struct selinux_audit_data___ig {
	u16 tclass;
} __attribute__((preserve_access_index));

// selinux_audit_data sits in an anonymous union in the kernel; CO-RE field
// resolution looks through anonymous members, so it is declared directly here.
struct common_audit_data___ig {
	struct selinux_audit_data___ig *selinux_audit_data;
} __attribute__((preserve_access_index));

#ifndef barrier_var
#define barrier_var(var) asm volatile("" : "+r"(var))
#endif

// Longest permission name in the kernel's class map is 21 characters
// ("x509_certificate_load"), so 32 bytes holds any of them with the NUL.
#define PERM_NAME_LEN 32
// Room for the permission names of one event, formatted as "a b c".
#define PERMS_LEN 256
// The buffer is over-allocated by one name so that a write starting at the
// largest possible masked offset still fits, which is what lets the verifier
// accept the variable offset.
#define PERMS_BUF_LEN (PERMS_LEN + PERM_NAME_LEN)

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

	// Permission names decoded from the bitmasks above, read from the
	// running kernel's secclass_map. Empty when the address could not be
	// resolved or the class could not be validated, in which case the
	// corresponding *_unknown mask below carries every audited bit and the
	// names are rendered as hexadecimal instead.
	char requested_perms[PERMS_BUF_LEN];
	char denied_perms[PERMS_BUF_LEN];
	char audited_perms[PERMS_BUF_LEN];

	// Bits that could not be resolved to a permission name.
	__u32 requested_unknown;
	__u32 denied_unknown;
	__u32 audited_unknown;

	gadget_kernel_stack kstack_raw;
	struct gadget_user_stack ustack;
};

// The event is too large for the compiler to inline a __builtin_memset(), and
// BPF cannot call out to memset(). Copy a zeroed .rodata instance instead.
static const struct event empty_event = {};

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

// The tclass index collected by the kprobe, handed over to the tracepoint the
// same way the user stack is. The tracepoint only receives the class *name*;
// indexing secclass_map needs the numeric index, which is only available from
// struct selinux_audit_data in the kprobe.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u16);
} ig_selinux_tclass SEC(".maps");

// Returns the address of secclass_map[tclass - 1], or 0 if unavailable.
static __always_inline __u64 secclass_map_entry(__u16 tclass)
{
	__u64 base = (__u64)&secclass_map;

	if (!base || tclass == 0)
		return 0;

	return base +
	       (__u64)(tclass - 1) *
		       bpf_core_type_size(struct security_class_mapping___ig);
}

// Reads secclass_map[tclass - 1].name and compares it with the class name the
// tracepoint reported. This validates in one step that the kallsyms address is
// correct, that the index matches the event, and that the struct layout was
// relocated properly. Without it, a wrong address would silently produce
// plausible-looking but incorrect permission names.
static __always_inline bool secclass_entry_matches(__u64 entry,
						   const char *tclass_name)
{
	char name[TCLASS_LEN];
	const char *name_ptr;

	if (bpf_probe_read_kernel(
		    &name_ptr, sizeof(name_ptr),
		    (void *)(entry + bpf_core_field_offset(
					     struct security_class_mapping___ig,
					     name))))
		return false;

	if (!name_ptr)
		return false;

	if (bpf_probe_read_kernel_str(name, sizeof(name), name_ptr) < 0)
		return false;

	for (int i = 0; i < TCLASS_LEN; i++) {
		if (name[i] != tclass_name[i])
			return false;
		if (name[i] == '\0')
			return true;
	}

	return false;
}

// Formats the permission names for the bits set in mask into out, mirroring
// avc_audit_pre_callback(). Bits with no name in secclass_map are returned in
// *unknown so they can be rendered as a single hexadecimal value, exactly as
// the kernel does.
static __always_inline void decode_perms(__u64 entry, __u32 mask, char *out,
					 __u32 *unknown)
{
	__u32 perms_off = bpf_core_field_offset(
		struct security_class_mapping___ig, perms);
	__u32 off = 0;
	bool full = false;

	*unknown = 0;

	if (!entry) {
		*unknown = mask;
		return;
	}

	// Do not unroll: 32 unrolled iterations times three masks blows past
	// the verifier's 1M instruction limit. As a bounded loop the verifier
	// walks the body once and prunes it against the previous iterations.
#pragma clang loop unroll(disable)
	for (int i = 0; i < 32; i++) {
		const char *perm_ptr;
		long len;

		if (!(mask & (1u << i)))
			continue;

		if (bpf_probe_read_kernel(&perm_ptr, sizeof(perm_ptr),
					  (void *)(entry + perms_off +
						   i * sizeof(perm_ptr))) ||
		    !perm_ptr) {
			*unknown |= (1u << i);
			continue;
		}

		// Stop before the buffer is full; remaining bits are reported
		// as unknown rather than being silently dropped. The separator
		// needs one byte too, hence PERMS_LEN - 1.
		if (full || off >= PERMS_LEN - 1) {
			full = true;
			*unknown |= (1u << i);
			continue;
		}

		// barrier_var() before each clamp, otherwise LLVM reloads the
		// spilled copy of off that the verifier has not narrowed and
		// the bound is lost. Masking (rather than only comparing) also
		// gives off the same [0, PERMS_LEN - 1] tnum on every
		// iteration, which is what lets the verifier prune states
		// instead of walking 32 ever-growing ranges.
		barrier_var(off);
		off &= PERMS_LEN - 2;

		if (off > 0) {
			out[off] = ' ';
			off++;
		}

		barrier_var(off);
		off &= PERMS_LEN - 1;

		// off <= PERMS_LEN - 1 and the read is at most PERM_NAME_LEN
		// bytes, so it always stays inside the PERMS_BUF_LEN buffer.
		len = bpf_probe_read_kernel_str(out + off, PERM_NAME_LEN,
						perm_ptr);
		if (len <= 0) {
			*unknown |= (1u << i);
			continue;
		}

		// len includes the NUL terminator.
		off += len - 1;
	}
}

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
	__u16 tclass;

	if (gadget_should_discard_data_current())
		return 0;

	tid = (__u32)bpf_get_current_pid_tgid();

	// Stash the class index for the tracepoint. Unlike the user stack, this
	// is needed for every event, so it is collected unconditionally.
	{
		struct common_audit_data___ig *ad;

		ad = (struct common_audit_data___ig *)PT_REGS_PARM2(ctx);
		tclass = BPF_CORE_READ(ad, selinux_audit_data, tclass);
		bpf_map_update_elem(&ig_selinux_tclass, &tid, &tclass, BPF_ANY);
	}

	if (!collect_ustack || !collect_otel_stack)
		return 0;

	__builtin_memset(&ustack, 0, sizeof(ustack));
	gadget_get_user_stack_from_kprobe(ctx, &ustack);

	bpf_map_update_elem(&ig_selinux_ustacks, &tid, &ustack, BPF_ANY);

	return 0;
}

SEC("tracepoint/avc/selinux_audited")
int ig_selinux(struct trace_event_raw_selinux_audited *ctx)
{
	struct gadget_user_stack ustack;
	struct event *event;
	__u32 tid;
	__u16 tclass = 0;
	__u16 *pending_tclass;

	__builtin_memset(&ustack, 0, sizeof(ustack));

	tid = (__u32)bpf_get_current_pid_tgid();

	// Drain the class index and the stack collected by the kprobe before any
	// early return below, so that a filtered-out event never leaves an entry
	// behind for a later event to pick up.
	pending_tclass = bpf_map_lookup_elem(&ig_selinux_tclass, &tid);
	if (pending_tclass) {
		tclass = *pending_tclass;
		bpf_map_delete_elem(&ig_selinux_tclass, &tid);
	}

	if (collect_ustack && collect_otel_stack) {
		struct gadget_user_stack *pending;

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
	bpf_probe_read_kernel(event, sizeof(*event), &empty_event);
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

	{
		__u64 entry = secclass_map_entry(tclass);

		if (entry && !secclass_entry_matches(entry, event->tclass))
			entry = 0;

		decode_perms(entry, event->requested, event->requested_perms,
			     &event->requested_unknown);
		decode_perms(entry, event->denied, event->denied_perms,
			     &event->denied_unknown);
		decode_perms(entry, event->audited, event->audited_perms,
			     &event->audited_unknown);
	}

	if (collect_kstack)
		event->kstack_raw = gadget_get_kernel_stack(ctx);
	else
		event->kstack_raw = GADGET_KERNEL_STACK_ID_NONE;

	if (collect_ustack && collect_otel_stack)
		event->ustack = ustack;
	else
		gadget_get_user_stack_from_tracepoint(ctx, &event->ustack);

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
