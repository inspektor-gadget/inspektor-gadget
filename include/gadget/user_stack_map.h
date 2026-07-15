// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 The Inspektor Gadget authors

#ifndef __USER_STACK_MAP_H
#define __USER_STACK_MAP_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include <gadget/types.h>
#include <gadget/macros.h>
#include <gadget/fnv1a.h>
#include <gadget/core_fixes.bpf.h>

const volatile bool collect_ustack = false;
GADGET_PARAM(collect_ustack);

#define GADGET_USER_MAX_STACK_DEPTH 127
#define GADGET_USER_STACK_MAP_MAX_ENTRIES 10000

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, GADGET_USER_MAX_STACK_DEPTH * sizeof(u64));
	__uint(max_entries, GADGET_USER_STACK_MAP_MAX_ENTRIES);
} ig_ustack SEC(".maps");

const volatile bool collect_build_id = false;
GADGET_PARAM(collect_build_id);

const volatile bool collect_otel_stack = false;
GADGET_PARAM(collect_otel_stack);

const volatile int ig_build_id_max_entries = 1024;
GADGET_PARAM(ig_build_id_max_entries);

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size,
	       GADGET_USER_MAX_STACK_DEPTH * sizeof(struct bpf_stack_build_id));
	__uint(max_entries, 0); // To be replaced at runtime
} ig_build_id SEC(".maps");

static const struct bpf_stack_build_id
	ig_empty_build_id[GADGET_USER_MAX_STACK_DEPTH] = {};

struct generic_param {
	u64 correlation_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct generic_param);
} otel_generic_params SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
	__array(values, int());
} otel_tc_kprobe SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
	__array(values, int());
} otel_tc_perf SEC(".maps");

// Linux v4.0 - v4.17
struct timespec___obsolete {
	__kernel_old_time_t tv_sec;
	long tv_nsec;
};
struct inode___with_timespec {
	struct timespec___obsolete i_mtime;
};

// Linux v4.18 - v6.6
// https://github.com/torvalds/linux/commit/95582b00838837fc07e042979320caf917ce3fe6
struct inode___with_timespec64 {
	struct timespec64 i_mtime;
};

// Linux 6.7 - v6.10
// https://github.com/torvalds/linux/commit/12cd44023651666bd44baa36a5c999698890debb
struct inode___with_timespec64_underscore {
	struct timespec64 __i_mtime;
};

// Linux v6.11 - v6.14-rc2
// https://github.com/torvalds/linux/commit/3aa63a569c64e708df547a8913c84e64a06e7853
struct inode___with_two_fields {
	time64_t i_mtime_sec;
	u32 i_mtime_nsec;
};

static __always_inline void
gadget_inode_get_mtime(struct inode *inode, __u64 *mtime_sec, __u32 *mtime_nsec)
{
	// There are 4 variants for the mtime fields in the inode struct. They can
	// vary by name, by type, and/or both. So we need to check both the name
	// (bpf_core_field_exists) and the type (bpf_core_field_size) of the field.

	// Linux v6.11 - v6.14-rc2
	// https://github.com/torvalds/linux/commit/3aa63a569c64e708df547a8913c84e64a06e7853
	if (bpf_core_field_exists(struct inode___with_two_fields,
				  i_mtime_sec) &&
	    bpf_core_field_size(struct inode___with_two_fields, i_mtime_sec) ==
		    sizeof(time64_t)) {
		struct inode___with_two_fields *inode_with_two_fields =
			(struct inode___with_two_fields *)inode;
		*mtime_sec = BPF_CORE_READ(inode_with_two_fields, i_mtime_sec);
		*mtime_nsec =
			BPF_CORE_READ(inode_with_two_fields, i_mtime_nsec);

		return;
	}

	// Linux 6.7 - v6.10
	// https://github.com/torvalds/linux/commit/12cd44023651666bd44baa36a5c999698890debb
	if (bpf_core_field_exists(struct inode___with_timespec64_underscore,
				  __i_mtime) &&
	    bpf_core_field_size(struct inode___with_timespec64_underscore,
				__i_mtime) == sizeof(struct timespec64)) {
		struct inode___with_timespec64_underscore
			*inode_with_timespec64_underscore =
				(struct inode___with_timespec64_underscore *)
					inode;
		*mtime_sec = BPF_CORE_READ(inode_with_timespec64_underscore,
					   __i_mtime.tv_sec);
		*mtime_nsec = BPF_CORE_READ(inode_with_timespec64_underscore,
					    __i_mtime.tv_nsec);

		return;
	}

	// Linux v4.18 - v6.6
	// https://github.com/torvalds/linux/commit/95582b00838837fc07e042979320caf917ce3fe6
	if (bpf_core_field_exists(struct inode___with_timespec64, i_mtime) &&
	    bpf_core_field_size(struct inode___with_timespec64, i_mtime) ==
		    sizeof(struct timespec64)) {
		struct inode___with_timespec64 *inode_with_timespec64 =
			(struct inode___with_timespec64 *)inode;
		*mtime_sec =
			BPF_CORE_READ(inode_with_timespec64, i_mtime.tv_sec);
		*mtime_nsec =
			BPF_CORE_READ(inode_with_timespec64, i_mtime.tv_nsec);

		return;
	}

	// Linux v4.0 - v4.17
	if (bpf_core_field_exists(struct inode___with_timespec, i_mtime) &&
	    bpf_core_field_size(struct inode___with_timespec, i_mtime) ==
		    sizeof(struct timespec___obsolete)) {
		struct inode___with_timespec *inode_with_timespec =
			(struct inode___with_timespec *)inode;
		*mtime_sec = BPF_CORE_READ(inode_with_timespec, i_mtime.tv_sec);
		*mtime_nsec =
			BPF_CORE_READ(inode_with_timespec, i_mtime.tv_nsec);

		return;
	}
}

static __always_inline u32 gadget_get_base_addr_hash(struct task_struct *task)
{
	u32 hash = fnv_32a_init();
	fnv_32a_update_u64(&hash, (u64)BPF_CORE_READ(task, mm));
	fnv_32a_update_u64(&hash, (u64)BPF_CORE_READ(task, mm, start_code));
	fnv_32a_update_u64(&hash, (u64)BPF_CORE_READ(task, mm, start_stack));
	return hash;
}

static __attribute__((noinline)) int
gadget_fetch_otel_stack_from_kprobe(void *ctx)
{
	u32 key = 0;
	bpf_tail_call(ctx, &otel_tc_kprobe, key);
	return 0;
}

static __attribute__((noinline)) int
gadget_fetch_otel_stack_from_perf_event(void *ctx)
{
	u32 key = 0;
	bpf_tail_call(ctx, &otel_tc_perf, key);
	return 0;
}

/* __gadget_fill_user_stack fills the user stack into ustack if collect_ustack is
 * true, or initializes ustack to 0 otherwise. It performs everything except the
 * OTel correlation-id fetch, which is program-type specific and handled by the
 * gadget_get_user_stack_from_{kprobe,perf_event} wrappers below.
 */
static __always_inline void
__gadget_fill_user_stack(void *ctx, struct gadget_user_stack *ustack)
{
	if (!collect_ustack) {
		ustack->major = 0;
		ustack->minor = 0;
		ustack->inode = 0;
		ustack->mtime_sec = 0;
		ustack->mtime_nsec = 0;
		ustack->base_addr_hash = 0;
		ustack->stack_id = 0;
		ustack->tgid_level0 = 0;
		ustack->pid_level0 = 0;
		ustack->pidns_level0 = 0;
		ustack->pid_level1 = 0;
		ustack->pidns_level1 = 0;
		ustack->otel_correlation_id = 0;
		ustack->boot_timestamp = 0;
		return;
	}

	ustack->stack_id = bpf_get_stackid(
		ctx, &ig_ustack, BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK);

	ustack->boot_timestamp = bpf_ktime_get_boot_ns();

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct inode *inode = BPF_CORE_READ(task, mm, exe_file, f_inode);

	struct pid *thread_pid = BPF_CORE_READ(task, thread_pid);
	unsigned int level = BPF_CORE_READ(thread_pid, level);
	// Cast pointer to "struct upid *" to avoid compilation warning in a way
	// that works both on Linux < v6.5 and >= v6.5. See:
	// https://github.com/torvalds/linux/commit/b69f0aeb068980af983d399deafc7477cec8bc04
	struct upid *numbers = (struct upid *)&thread_pid->numbers;

	ustack->tgid_level0 = BPF_CORE_READ(task, tgid);
	ustack->pid_level0 = BPF_CORE_READ(numbers, nr);
	ustack->pidns_level0 = BPF_CORE_READ(numbers, ns, ns.inum);
	if (level >= 1) {
		numbers += 1;
		ustack->pid_level1 = BPF_CORE_READ(numbers, nr);
		ustack->pidns_level1 = BPF_CORE_READ(numbers, ns, ns.inum);
	} else {
		ustack->pid_level1 = 0;
		ustack->pidns_level1 = 0;
	}

	// dev_t kernel encoding explained here:
	// https://github.com/torvalds/linux/blob/v6.12/include/linux/kdev_t.h#L7-L12
	// This is different to the way stat's st_dev is encoded in user space.
	// So we use the u64 major and minor device numbers to ensure hash compatibility
	// with user space.
	dev_t dev = BPF_CORE_READ(inode, i_sb, s_dev);
	ustack->major = (u32)((unsigned int)((dev) >> 20));
	ustack->minor = (u32)((unsigned int)((dev) & ((1U << 20) - 1)));
	ustack->inode = (u64)BPF_CORE_READ(inode, i_ino);
	gadget_inode_get_mtime(inode, &ustack->mtime_sec, &ustack->mtime_nsec);

	ustack->base_addr_hash = gadget_get_base_addr_hash(task);

	// otel_correlation_id is filled by the program-type specific wrapper.
	ustack->otel_correlation_id = 0;

	if (collect_build_id && ustack->stack_id >= 0) {
		int already_exists =
			bpf_map_update_elem(&ig_build_id, &ustack->stack_id,
					    &ig_empty_build_id, BPF_NOEXIST);
		if (already_exists != 0)
			return;
		struct bpf_stack_build_id *build_id =
			bpf_map_lookup_elem(&ig_build_id, &ustack->stack_id);
		if (!build_id)
			return;

		int ret =
			bpf_get_stack(ctx, build_id,
				      GADGET_USER_MAX_STACK_DEPTH *
					      sizeof(struct bpf_stack_build_id),
				      BPF_F_USER_STACK | BPF_F_USER_BUILD_ID);
		if (ret < 0)
			return;
	}
}

// __gadget_read_otel_correlation reads the OTel correlation id that the OTel
// entry program wrote to the shared otel_generic_params map during the tail
// call, and stores it in ustack.
static __always_inline void
__gadget_read_otel_correlation(struct gadget_user_stack *ustack)
{
	struct generic_param *ret_param;
	int zero = 0;
	ret_param = bpf_map_lookup_elem(&otel_generic_params, &zero);
	if (!ret_param)
		return;

	ustack->otel_correlation_id = ret_param->correlation_id;
}

/* gadget_get_user_stack_from_kprobe gets the user stack (and, if
 * collect_otel_stack is set, the OTel correlation id) for a gadget program of
 * type BPF_PROG_TYPE_KPROBE (kprobe, kretprobe, uprobe, uretprobe).
 */
static __always_inline void
gadget_get_user_stack_from_kprobe(void *ctx, struct gadget_user_stack *ustack)
{
	__gadget_fill_user_stack(ctx, ustack);

	if (collect_ustack && collect_otel_stack) {
		gadget_fetch_otel_stack_from_kprobe(ctx);
		__gadget_read_otel_correlation(ustack);
	}
}

/* gadget_get_user_stack_from_perf_event gets the user stack (and, if
 * collect_otel_stack is set, the OTel correlation id) for a gadget program of
 * type BPF_PROG_TYPE_PERF_EVENT.
 */
static __always_inline void
gadget_get_user_stack_from_perf_event(void *ctx,
				      struct gadget_user_stack *ustack)
{
	__gadget_fill_user_stack(ctx, ustack);

	if (collect_ustack && collect_otel_stack) {
		gadget_fetch_otel_stack_from_perf_event(ctx);
		__gadget_read_otel_correlation(ustack);
	}
}

/* gadget_get_user_stack_from_tracepoint gets the user stack for a gadget program
 * whose type cannot use OTel symbolization (e.g. BPF_PROG_TYPE_TRACEPOINT). The
 * plain user stack is always collected and remains symbolizable by the
 * symbol-table symbolizer.
 *
 * OTel symbolization relies on a correlation id produced by a bpf_tail_call that
 * requires a matching program type, which a tracepoint program cannot satisfy,
 * so requesting it here is unsupported. Rather than reference an incompatible
 * OTel prog-array (or silently return an empty correlation id),
 * bpf_core_unreachable() makes the loader reject the program if OTel stacks are
 * requested. Because collect_otel_stack is a const-volatile param, the verifier
 * prunes this branch entirely when it is unset (the common case), so the guard
 * is zero-cost and references no OTel prog-array.
 */
static __always_inline void
gadget_get_user_stack_from_tracepoint(void *ctx,
				      struct gadget_user_stack *ustack)
{
	__gadget_fill_user_stack(ctx, ustack);

	if (collect_ustack && collect_otel_stack)
		bpf_core_unreachable();
}

/* gadget_get_user_stack dispatches to the program-type-correct variant based on
 * the static C type of ctx, resolved at compile time by _Generic. Only the
 * selected variant's bpf_tail_call survives in the program, so each program
 * references only its own OTel prog-array (otel_tc_kprobe or otel_tc_perf) and
 * the kernel prog-array type lock (bpf_prog_array_compatible) is never hit.
 *
 *   struct bpf_perf_event_data *  -> perf_event variant
 *   struct pt_regs *              -> kprobe variant (also covers
 *                                    kretprobe/uprobe/uretprobe, which are all
 *                                    BPF_PROG_TYPE_KPROBE)
 *
 * There is deliberately no default association: a ctx of any other type (e.g. a
 * tracepoint ctx or a plain void *) is a compile-time error ("controlling
 * expression type ... not compatible with any generic association type").
 * Tracepoint gadgets should call gadget_get_user_stack_from_tracepoint() (user
 * stack only, no OTel symbolization); other program types should call the
 * matching gadget_get_user_stack_from_{kprobe,perf_event}() helper directly.
 */
#define gadget_get_user_stack(ctx, ustack)                                           \
	_Generic((ctx),                                                              \
		struct bpf_perf_event_data *: gadget_get_user_stack_from_perf_event, \
		struct pt_regs *: gadget_get_user_stack_from_kprobe)((ctx),          \
								     (ustack))

#endif /* __USER_STACK_MAP_H */
