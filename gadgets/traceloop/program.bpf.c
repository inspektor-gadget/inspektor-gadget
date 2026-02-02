// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <gadget/mntns.h>
#include <gadget/mntns_filter.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#define PARAM_LEN 128

/* The syscall can have max 6 arguments. */
#define SYSCALL_ARGS 6

/* 16 syscalls should be enough to filter out. */
#define SYSCALL_FILTERS 16

const __u64 PARAM_PROBE_AT_EXIT_MASK = 0xf000000000000000ULL;
const __u64 USE_RET_AS_PARAM_LENGTH = 0x0ffffffffffffffeULL;

/* Special values used to refer to dynamic length. */
const __u64 USE_NULL_BYTE_LENGTH = 0x0fffffffffffffffULL;

/*
 * INDEX(x) is not defined (Cgo cannot access macros),
 * use bit arithmetic with mask below to get value and use addition to generate.
 * The current maximum of parameters is 6, so that means only values until 5 may
 * be added to specify the index. The other theoretical limit is 13 since
 * 14 and 15 are reserved as written above 0xff (null-byte length) and
 * 0xfe (ret as param. length).
 */
const __u64 USE_ARG_INDEX_AS_PARAM_LENGTH = 0x0ffffffffffffff0ULL;
const __u64 USE_ARG_INDEX_AS_PARAM_LENGTH_MASK = 0xfULL;

enum event_type {
	SYSCALL_EVENT_TYPE_ENTER = 0,
	SYSCALL_EVENT_TYPE_EXIT = 1,
	SYSCALL_EVENT_TYPE_CONT = 2
};

struct syscall_event_t {
	/*
	 * event_type must be the first field.
	 * So, userspace can figure out the type of events in the ring buffer.
	 */
	enum event_type event_type;

	/* __u64 ret stored in args[0] */
	__u64 args[SYSCALL_ARGS];
	__u64 monotonic_timestamp;
	__u64 boot_timestamp;
	__u32 pid;

	__u16 cpu;
	__u16 id;
	__u8 comm[TASK_COMM_LEN];
	/* how many syscall_event_cont_t messages to expect after */
	__u8 cont_nr;

	__u8 padding[60];
};

struct syscall_event_cont_t {
	/*
	 * event_type must be the first field.
	 * So, userspace can figure out the type of events in the ring buffer.
	 */
	enum event_type event_type;

	__u8 param[PARAM_LEN];
	__u64 monotonic_timestamp;
	__u64 length;
	__u8 index;
	__u8 failed;
};

_Static_assert(
	sizeof(struct syscall_event_cont_t) == sizeof(struct syscall_event_t),
	"syscall_event_t and syscall_event_cont_t must have the same size as API does not permit having different sizes");

struct syscall_def_t {
	__u64 args_len[SYSCALL_ARGS];
};

struct remembered_args {
	__u64 monotonic_timestamp;
	__u64 nr;
	__u64 args[SYSCALL_ARGS];
};

/*
 * Taken from:
 * https://github.com/seccomp/libseccomp/blob/afbde6ddaec7c58c3b281d43b0b287269ffca9bd/src/syscalls.csv
 */
#if defined(__TARGET_ARCH_arm64)
#define __NR_rt_sigreturn 139
#define __NR_exit_group 94
#define __NR_exit 93
#elif defined(__TARGET_ARCH_x86)
#define __NR_rt_sigreturn 15
#define __NR_exit_group 231
#define __NR_exit 60
#else
#error "Traceloop is not supported on your architecture."
#endif

/*
 * Add the following in build.yaml to print debug messages:
 *  cflags: '-DSHOW_DEBUG'
 */
#if defined(SHOW_DEBUG)
#define bpf_debug_printk(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else /* !defined(SHOW_DEBUG) */
#define bpf_debug_printk(fmt, ...) \
	do {                       \
	} while (0)
#endif /* !defined(SHOW_DEBUG) */

/*
 * Add the following in build.yaml to print error messages:
 *  cflags: '-DSHOW_ERROR'
 */
#if defined(SHOW_ERROR)
#define bpf_error_printk(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else /* !defined(SHOW_ERROR) */
#define bpf_error_printk(fmt, ...) \
	do {                       \
	} while (0)
#endif /* !defined(SHOW_ERROR) */

const struct syscall_event_t *unused_event __attribute__((unused));
const struct syscall_event_cont_t *unused_event_cont __attribute__((unused));

/*
 * We need this to avoid hitting the 512 bytes stack limit.
 * Indeed, pt_regs contains several u64 fields, so it is quite big.
 */
static const struct pt_regs empty;
static struct syscall_def_t default_definition;
static const struct syscall_event_t empty_syscall_event = {};
static const struct syscall_event_cont_t empty_syscall_cont_event = {};

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	/*
	 * We will use mount namespace ID to get the perf buffer corresponding
	 * to this container.
	 */
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 1024);
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
			__uint(key_size, sizeof(u32));
			__uint(value_size, sizeof(u32));
		});
} map_of_perf_buffers SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(struct syscall_def_t));
	/*
	 * For now, we only support 22 syscalls, let's use the immediate greater
	 * power of 2.
	 * This value should be increased when new syscalls are added to
	 * syscallDefs in program.go.
	 */
	__uint(max_entries, 32);
} syscalls SEC(".maps");

/*
 * This key/value store maps thread PIDs to syscall arg arrays
 * that were remembered at sys_enter so that sys_exit can probe buffer
 * contents and generate syscall events showing the result content.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(struct remembered_args));
	__uint(max_entries, 1024);
} probe_at_sys_exit SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(struct pt_regs));
	__uint(max_entries, 1024);
} regs_map SEC(".maps");

/*
 * syscall_event_t and syscall_event_cont_t are big structures, let store them
 * here instead of using the stack.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct syscall_event_t));
	__uint(max_entries, 1);
} fake_stack SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u64));
	/*
	 * We do not care about the value here, so let's use a bool to consume one
	 * byte per value.
	 */
	__uint(value_size, sizeof(bool));
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, SYSCALL_FILTERS);
} syscall_filters SEC(".maps");

// the below map is a surrogate for the --sycall-filters parameter
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32); // index: zero
	__type(value, bool);
} syscall_enable_filters SEC(".maps");

void *fake_stack_alloc(const void *event)
{
	u32 zero = 0;

	if (bpf_map_update_elem(&fake_stack, &zero, event, BPF_ANY))
		return NULL;

	return bpf_map_lookup_elem(&fake_stack, &zero);
}

static __always_inline int skip_exit_probe(int nr)
{
	return !!(nr == __NR_exit || nr == __NR_exit_group ||
		  nr == __NR_rt_sigreturn);
}

static __always_inline bool should_filter_out_syscall(u64 syscall_nr)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&syscall_enable_filters, &zero) != NULL &&
	       bpf_map_lookup_elem(&syscall_filters, &syscall_nr) == NULL;
}

/*
 * Highly inspired from ksnoop.bpf.c:
 * https://github.com/iovisor/bcc/blob/f90126bb3770ea1bdd915ff3b47e451c6dde5c40/libbpf-tools/ksnoop.bpf.c#L280
 */
static __always_inline u64 get_arg(struct pt_regs *regs, int i)
{
	switch (i) {
	case 1:
		return PT_REGS_PARM1_CORE_SYSCALL(regs);
	case 2:
		return PT_REGS_PARM2_CORE_SYSCALL(regs);
	case 3:
		return PT_REGS_PARM3_CORE_SYSCALL(regs);
	case 4:
		return PT_REGS_PARM4_CORE_SYSCALL(regs);
	case 5:
		return PT_REGS_PARM5_CORE_SYSCALL(regs);
	case 6:
		return PT_REGS_PARM6_CORE_SYSCALL(regs);
	default:
		bpf_error_printk(
			"There is no PT_REGS_PARM%d_SYSCALL macro, check the argument!",
			i);
		return 0;
	}
}

/*
 * sys_enter is defined as:
 * TP_PROTO(struct pt_regs *regs, long id)
 * (https://elixir.bootlin.com/linux/v5.19/source/include/trace/events/syscalls.h#L20)
 * So, ctx->args[0] contains a struct pt_regs and ctx->args[1] the syscall ID.
 */
SEC("raw_tracepoint/sys_enter")
int ig_traceloop_e(struct bpf_raw_tracepoint_args *ctx)
{
	u64 mntns_id = gadget_get_current_mntns_id();
	struct remembered_args remembered = {};
	u64 pid = bpf_get_current_pid_tgid();
	struct syscall_def_t *syscall_def;
	struct syscall_event_t *sc;
	u64 nr = ctx->args[1];
	struct pt_regs *args;
	void *perf_buffer;
	int ret;
	int i;

	if (should_filter_out_syscall(nr))
		return 0;

	perf_buffer = bpf_map_lookup_elem(&map_of_perf_buffers, &mntns_id);
	if (!perf_buffer)
		return 0;

	sc = fake_stack_alloc(&empty_syscall_event);
	if (!sc)
		return 0;

	/*
	 * The boot time timestamp is used to give the timestamp to users. It
	 * is converted to the wall-clock time in userspace. It only works
	 * from Linux 5.7. On older kernels, the BPF bytecode for
	 * bpf_ktime_get_boot_ns is automatically removed by the BPF loader,
	 * see FixBpfKtimeGetBootNs. In this way, this BPF program can still be
	 * loaded on older kernels.
	 */
	u64 boot_ts = bpf_ktime_get_boot_ns();

	/*
	 * The monotonic timestamp is used by traceloop to match the sys_enter
	 * event with the cont and sys_exit events. This is an internal
	 * implementation detail not exposed to the user.
	 */
	u64 monotonic_ts = bpf_ktime_get_ns();

	sc->event_type = SYSCALL_EVENT_TYPE_ENTER;
	sc->boot_timestamp = boot_ts;
	sc->monotonic_timestamp = monotonic_ts;
	sc->cont_nr = 0;
	sc->cpu = bpf_get_smp_processor_id();
	sc->pid = pid >> 32;
	sc->id = nr;

	remembered.monotonic_timestamp = monotonic_ts;
	remembered.nr = nr;

	syscall_def = bpf_map_lookup_elem(&syscalls, &nr);
	/*
	 * syscalls map contains definition for specific syscall like read or
	 * write.
	 * All others syscalls, like nanosleep, are not in this map because
	 * their signature is not specific, in this case, we use the default
	 * definition.
	 */
	if (syscall_def == NULL)
		syscall_def = &default_definition;

	bpf_get_current_comm(sc->comm, sizeof(sc->comm));

	ret = bpf_map_update_elem(&regs_map, &pid, &empty, BPF_NOEXIST);
	if (ret) {
		bpf_error_printk(
			"enter: there should not be any pt_regs for key %lu: %d",
			pid, ret);

		goto end;
	}

	args = bpf_map_lookup_elem(&regs_map, &pid);
	if (!args) {
		bpf_error_printk("enter: there should be a pt_regs for key %lu",
				 pid);

		goto end;
	}

	bpf_probe_read_kernel(args, sizeof(*args), (void *)ctx->args[0]);

	for (i = 0; i < SYSCALL_ARGS; i++) {
		/* + 1 because PT_REGS_PARM begins from 1. */
		u64 arg = get_arg(args, i + 1);
		sc->args[i] = arg;
		remembered.args[i] = arg;
		if (syscall_def->args_len[i])
			sc->cont_nr++;
	}

	bpf_debug_printk(
		"Perf event output: sc.id: %d; sc.comm: %s; sizeof(sc): %d",
		sc->id, sc->comm, sizeof(sc));
	ret = bpf_perf_event_output(ctx, perf_buffer, BPF_F_CURRENT_CPU, sc,
				    sizeof(*sc));
	if (ret != 0) {
		bpf_error_printk("Problem outputting perf event: %d", ret);
	}

	// Avoid using probe_at_sys_exit for exit() and exit_group() because sys_exit
	// would not be called and the map would not be cleaned up and would get full.
	// Note that a process can still get killed in the middle, so we would need
	// a userspace cleaner for this case (TODO).
	if (!skip_exit_probe(nr))
		bpf_map_update_elem(&probe_at_sys_exit, &pid, &remembered,
				    BPF_ANY);

// We need to unroll this loop to make this work on kernels 5.4.0-x on ubuntu, see
// https://github.com/inspektor-gadget/inspektor-gadget/issues/1465 for more details.
#pragma unroll
	for (i = 0; i < SYSCALL_ARGS; i++) {
		u64 arg_len = syscall_def->args_len[i];
		struct syscall_event_cont_t *sc_cont;

		if (!arg_len || (arg_len & PARAM_PROBE_AT_EXIT_MASK) ||
		    arg_len == USE_RET_AS_PARAM_LENGTH)
			continue;

		sc_cont = fake_stack_alloc(&empty_syscall_cont_event);
		if (!sc_cont)
			continue;

		sc_cont->event_type = SYSCALL_EVENT_TYPE_CONT;
		sc_cont->monotonic_timestamp = monotonic_ts;
		sc_cont->index = i;
		sc_cont->failed = false;

		bool null_terminated = false;
		if (arg_len == USE_NULL_BYTE_LENGTH) {
			null_terminated = true;
			arg_len = 0;
		} else if (arg_len >= USE_ARG_INDEX_AS_PARAM_LENGTH) {
			__u64 idx = arg_len &
				    USE_ARG_INDEX_AS_PARAM_LENGTH_MASK;

			/*
			 * Access args via the previously saved map entry instead of
			 * the ctx pointer or 'remembered' struct to avoid this verifier
			 * issue (which does not occur in sys_exit for the same code):
			 * "variable ctx access var_off=(0x0; 0x38) disallowed"
			 */
			struct remembered_args *remembered_ctx_workaround;
			if (idx < SYSCALL_ARGS) {
				remembered_ctx_workaround = bpf_map_lookup_elem(
					&probe_at_sys_exit, &pid);
				if (remembered_ctx_workaround)
					arg_len = remembered_ctx_workaround
							  ->args[idx];
				else
					arg_len = 0;
			} else {
				arg_len = PARAM_LEN;
			}
		}

		if (arg_len > sizeof(sc_cont->param))
			arg_len = sizeof(sc_cont->param);

		if (null_terminated)
			sc_cont->length = USE_NULL_BYTE_LENGTH;
		else
			sc_cont->length = arg_len;

		/* + 1 because PT_REGS_PARM begins from 1. */
		u64 arg = get_arg(args, i + 1);

		if (!arg_len &&
		    null_terminated /* NULL terminated argument like string */
		    && bpf_probe_read_user_str(sc_cont->param, PARAM_LEN,
					       (void *)(arg)) < 0)
			sc_cont->failed = true;
		else if (sizeof(u8) <= arg_len &&
			 arg_len <=
				 sizeof(u64) /* Conventional arguments like type (char, int, etc.) */
			 && bpf_probe_read_user(sc_cont->param, arg_len,
						(void *)(arg)))
			sc_cont->failed = true;
		else if (bpf_probe_read_user(
				 sc_cont->param, PARAM_LEN,
				 (void *)(arg))) /* TODO Struct arguments? */
			sc_cont->failed = true;

		bpf_debug_printk(
			"Perf event output: sc_cont.index: %d; sizeof(sc_cont): %d",
			sc_cont->index, sizeof(sc_cont));
		ret = bpf_perf_event_output(ctx, perf_buffer, BPF_F_CURRENT_CPU,
					    sc_cont, sizeof(*sc_cont));
		if (ret != 0) {
			bpf_error_printk(
				"Problem outputting continued perf event: %d",
				ret);
		}
	}

end:
	bpf_map_delete_elem(&regs_map, &pid);

	return 0;
}

/*
 * syscall_get_nr() is defined for each architecture in the Linux kernel.
 * As we cannot use trace_event_raw_sys_exit, we need to get the current syscall
 * number from the register.
 * So, this function should be expanded with the code of the architecture we
 * support.
 */
static __always_inline int syscall_get_nr(struct pt_regs *regs)
{
#if defined(__TARGET_ARCH_arm64)
	return regs->syscallno;
#elif defined(__TARGET_ARCH_x86)
	return regs->orig_ax;
#else
#error "Traceloop is not supported on your architecture."
#endif
}

/*
 * sys_exit is defined as:
 * TP_PROTO(struct pt_regs *regs, long ret),
 * (https://elixir.bootlin.com/linux/v5.19/source/include/trace/events/syscalls.h#L46)
 * So, ctx->args[0] contains a struct pt_regs and ctx->args[1] the syscall
 * return value.
 */
SEC("raw_tracepoint/sys_exit")
int ig_traceloop_x(struct bpf_raw_tracepoint_args *ctx)
{
	u64 mntns_id = gadget_get_current_mntns_id();
	u64 pid = bpf_get_current_pid_tgid();
	struct remembered_args *remembered;
	struct syscall_def_t *syscall_def;
	struct syscall_event_t *sc;
	long ret = ctx->args[1];
	struct pt_regs *args;
	void *perf_buffer;
	int i, r;
	u64 nr;

	perf_buffer = bpf_map_lookup_elem(&map_of_perf_buffers, &mntns_id);
	if (!perf_buffer)
		return 0;

	r = bpf_map_update_elem(&regs_map, &pid, &empty, BPF_NOEXIST);
	if (r) {
		bpf_error_printk(
			"exit: there should not be any pt_regs for key %lu: %d",
			pid, r);

		return 0;
	}

	args = bpf_map_lookup_elem(&regs_map, &pid);
	if (!args) {
		bpf_error_printk("exit: there should be a pt_regs for key %lu",
				 pid);

		goto end;
	}

	bpf_probe_read_kernel(args, sizeof(*args), (void *)ctx->args[0]);
	nr = syscall_get_nr(args);
	/* TODO Why this can occur? */
	if (nr == -1)
		goto end;

	sc = fake_stack_alloc(&empty_syscall_event);
	if (!sc)
		goto end;

	sc->event_type = SYSCALL_EVENT_TYPE_EXIT;
	sc->boot_timestamp = bpf_ktime_get_boot_ns();
	sc->cpu = bpf_get_smp_processor_id();
	sc->pid = pid >> 32;
	sc->id = nr;
	sc->args[0] = ret;

	syscall_def = bpf_map_lookup_elem(&syscalls, &nr);
	if (syscall_def == NULL)
		syscall_def = &default_definition;

	remembered = bpf_map_lookup_elem(&probe_at_sys_exit, &pid);
	if (!remembered)
		goto end;

	/*
	 * This ensures all events (enter, exit and cont) related to a given
	 * syscall have the same timestamp.
	 */
	sc->monotonic_timestamp = remembered->monotonic_timestamp;

	bpf_get_current_comm(sc->comm, sizeof(sc->comm));

	bpf_debug_printk(
		"Perf event output (exit): sc.id: %d; sc.comm: %s; sizeof(sc): %d",
		sc->id, sc->comm, sizeof(sc));
	r = bpf_perf_event_output(ctx, perf_buffer, BPF_F_CURRENT_CPU, sc,
				  sizeof(*sc));
	if (r != 0)
		bpf_error_printk("Problem outputting exit perf event: %d", ret);

	for (i = 0; i < SYSCALL_ARGS; i++) {
		u64 arg_len = syscall_def->args_len[i];
		struct syscall_event_cont_t *sc_cont;

		if (!arg_len || !(arg_len & PARAM_PROBE_AT_EXIT_MASK))
			goto end_loop;

		sc_cont = fake_stack_alloc(&empty_syscall_cont_event);
		if (!sc_cont)
			continue;

		sc_cont->event_type = SYSCALL_EVENT_TYPE_CONT;
		sc_cont->monotonic_timestamp = remembered->monotonic_timestamp;
		sc_cont->index = i;
		sc_cont->failed = false;

		bool null_terminated = false;
		arg_len &= ~PARAM_PROBE_AT_EXIT_MASK;

		if (arg_len == USE_RET_AS_PARAM_LENGTH) {
			if ((signed long)ret < 0)
				arg_len = 0;
			else
				arg_len = ret;
		} else if (arg_len == USE_NULL_BYTE_LENGTH) {
			null_terminated = true;
			arg_len = 0;
		} else if (arg_len >= USE_ARG_INDEX_AS_PARAM_LENGTH) {
			__u64 idx = arg_len &
				    USE_ARG_INDEX_AS_PARAM_LENGTH_MASK;
			if (idx < SYSCALL_ARGS)
				arg_len = remembered->args[idx];
			else
				arg_len = PARAM_LEN;
		}

		if (arg_len > sizeof(sc_cont->param))
			arg_len = sizeof(sc_cont->param);

		if (null_terminated)
			sc_cont->length = USE_NULL_BYTE_LENGTH;
		else
			sc_cont->length = arg_len;

		if (arg_len == 0 && null_terminated) {
			if (bpf_probe_read_user_str(
				    sc_cont->param, PARAM_LEN,
				    (void *)(remembered->args[i])) < 0)
				sc_cont->failed = true;
		} else if (sizeof(u8) <= arg_len && arg_len <= sizeof(u64) &&
			   bpf_probe_read_user(sc_cont->param, arg_len,
					       (void *)(remembered->args[i]))) {
			sc_cont->failed = true;
		} else if (bpf_probe_read_user(sc_cont->param, PARAM_LEN,
					       (void *)(remembered->args[i]))) {
			sc_cont->failed = true;
		}

		bpf_debug_printk(
			"Perf event output (continued): sc_cont.index: %d; sizeof(sc_cont): %d",
			sc_cont->index, sizeof(sc_cont));
		r = bpf_perf_event_output(ctx, perf_buffer, BPF_F_CURRENT_CPU,
					  sc_cont, sizeof(*sc_cont));
		if (r != 0) {
			bpf_error_printk(
				"Problem outputting continued perf event: %d",
				ret);
		}

end_loop:
		bpf_map_delete_elem(&probe_at_sys_exit, &pid);
	}

end:
	bpf_map_delete_elem(&regs_map, &pid);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
