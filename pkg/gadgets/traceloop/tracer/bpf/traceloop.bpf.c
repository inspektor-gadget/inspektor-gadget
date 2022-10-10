// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <vmlinux/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "traceloop.h"

/*
 * Taken from:
 * https://github.com/seccomp/libseccomp/blob/afbde6ddaec7c58c3b281d43b0b287269ffca9bd/src/syscalls.csv
 */
#if defined(__TARGET_ARCH_arm64)
#define __NR_exit 93
#define __NR_exit_group 94
/*
 * The kernel does not provide an helper macro to get the sixth argument from
 * syscalls.
 * So, we craft it ourselves using man syscall:
 * Arch/ABI      arg1  arg2  arg3  arg4  arg5  arg6  arg7  Notes
 * ─────────────────────────────────────────────────────────────
 * ...
 * arm64         x0    x1    x2    x3    x4    x5    -
 * ...
 * x86-64        rdi   rsi   rdx   r10   r8    r9    -
 */
#define PT_REGS_PARM6_CORE_SYSCALL(ctx) BPF_CORE_READ(ctx, regs[5])
#elif defined(__TARGET_ARCH_x86)
#define __NR_exit 60
#define __NR_exit_group 231
#define PT_REGS_PARM6_CORE_SYSCALL(ctx) BPF_CORE_READ(ctx, r9)
#else
#error "Traceloop was not ported to your architecture."
#endif

/* Comment this out to activate debug printing. */
#define bpf_debug_printk(fmt, ...)
#if !defined(bpf_debug_printk)
#define bpf_debug_printk(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#endif /* !defined(bpf_debug_printk) */

/*
 * We need this to avoid hitting the 512 bytes stack limit.
 * Indeed, pt_regs contains several u64 fields, so it is quite big.
 */
static const struct pt_regs empty;
static struct syscall_def_t default_definition;

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	/*
	 * We will use mount namespace ID to get the perf buffer corresponding
	 * to this container.
	 */
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 1024);
	__array(values, struct {
		__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
		__uint(key_size, sizeof(u32));
		__uint(value_size, sizeof(u32));
	});
} map_of_perf_buffers SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u16));
	__uint(value_size, sizeof(struct syscall_def_t));
	/*
	 * We have around 300 syscalls, let's use the immediate greater power of
	 * 2.
	 */
	__uint(max_entries, 512);
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

static inline int skip_exit_probe(int nr) {
	return !!(nr == __NR_exit || nr == __NR_exit_group);
}

/*
 * Highly inspired from ksnoop.bpf.c:
 * https://github.com/iovisor/bcc/blob/f90126bb3770ea1bdd915ff3b47e451c6dde5c40/libbpf-tools/ksnoop.bpf.c#L280
 */
static inline u64 get_arg(struct pt_regs *regs, int i)
{
	switch(i) {
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
		bpf_printk("There is no PT_REGS_PARM%d_SYSCALL macro, check the argument!\n", i);
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
	struct remembered_args remembered = {};
	u64 pid = bpf_get_current_pid_tgid();
	struct syscall_def_t *syscall_def;
	/*
	 * Initialize struct to empty to be sure all fields (even padding) are zeroed:
	 * https://github.com/iovisor/bcc/issues/2623#issuecomment-560214481
	 */
	struct syscall_event_t sc = {};
	u64 ts = bpf_ktime_get_ns();
	struct task_struct *task;
	u16 nr = ctx->args[1];
	struct pt_regs *args;
	void *perf_buffer;
	u64 mntns_id;
	int ret;
	int i;

	sc.timestamp = ts;
	sc.cont_nr = 0;
	sc.cpu = bpf_get_smp_processor_id();
	sc.pid = pid;
	sc.typ = SYSCALL_EVENT_TYPE_ENTER;
	sc.id = nr;

	remembered.timestamp = ts;
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

	task = (struct task_struct*)bpf_get_current_task();
	mntns_id = (u64) BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

	perf_buffer = bpf_map_lookup_elem(&map_of_perf_buffers, &mntns_id);
	if (!perf_buffer)
		return 0;

	bpf_get_current_comm(sc.comm, sizeof(sc.comm));

	ret = bpf_map_update_elem(&regs_map, &pid, &empty, BPF_NOEXIST);
	if (ret) {
		bpf_printk("enter: there should not be any pt_regs for key %lu: %d\n", pid, ret);

		return 0;
	}

	args = bpf_map_lookup_elem(&regs_map, &pid);
	if (!args) {
		bpf_printk("enter: there should be a pt_regs for key %lu\n", ts);

		goto end;
	}

	bpf_probe_read(args, sizeof(*args), (void*) ctx->args[0]);

	for (i = 0; i < SYSCALL_ARGS; i++) {
		/* + 1 because PT_REGS_PARM begins from 1. */
		u64 arg = get_arg(args, i + 1);
		sc.args[i] = arg;
		remembered.args[i] = arg;
		sc.cont_nr += !!syscall_def->args_len[i];
	}

	bpf_debug_printk("Perf event output: sc.id: %d; sc.comm: %s; sizeof(sc): %d\n", sc.id, sc.comm, sizeof(sc));
	bpf_perf_event_output(ctx, perf_buffer, BPF_F_CURRENT_CPU, &sc,
			      sizeof(sc));

	// Avoid using probe_at_sys_exit for exit() and exit_group() because sys_exit
	// would not be called and the map would not be cleaned up and would get full.
	// Note that a process can still get killed in the middle, so we would need
	// a userspace cleaner for this case (TODO).
	if (!skip_exit_probe(nr))
		bpf_map_update_elem(&probe_at_sys_exit, &pid, &remembered, BPF_ANY);

	for (i = 0; i < SYSCALL_ARGS; i++) {
		__u64 arg_len = syscall_def->args_len[i];

		if (!arg_len || (arg_len & PARAM_PROBE_AT_EXIT_MASK) || arg_len == USE_RET_AS_PARAM_LENGTH)
			continue;

		bool null_terminated = false;
		struct syscall_event_cont_t sc_cont = {};

		sc_cont.timestamp = ts;
		sc_cont.index = i;
		sc_cont.failed = false;

		if (arg_len == USE_NULL_BYTE_LENGTH) {
			null_terminated = true;
			arg_len = 0;
		} else if (arg_len >= USE_ARG_INDEX_AS_PARAM_LENGTH) {
			__u64 idx = arg_len & USE_ARG_INDEX_AS_PARAM_LENGTH_MASK;

			/*
			 * Access args via the previously saved map entry instead of
			 * the ctx pointer or 'remembered' struct to avoid this verifier
			 * issue (which does not occur in sys_exit for the same code):
			 * "variable ctx access var_off=(0x0; 0x38) disallowed"
			 */
			struct remembered_args *remembered_ctx_workaround;
			if (idx < SYSCALL_ARGS) {
				remembered_ctx_workaround = bpf_map_lookup_elem(&probe_at_sys_exit, &pid);
				if (remembered_ctx_workaround)
					arg_len = remembered_ctx_workaround->args[idx];
				else
					arg_len = 0;
			} else {
				arg_len = PARAM_LEN;
			}
		}

		if (arg_len > sizeof(sc_cont.param))
			arg_len = sizeof(sc_cont.param);

		if (null_terminated)
			sc_cont.length = USE_NULL_BYTE_LENGTH;
		else
			sc_cont.length = arg_len;

		/* + 1 because PT_REGS_PARM begins from 1. */
		u64 arg = get_arg(args, i + 1);

		// Call bpf_probe_read() with a constant size to avoid errors on 4.14.137+
		// invalid stack type R1 off=-304 access_size=0
		// Possibly related:
		// https://github.com/torvalds/linux/commit/9fd29c08e52023252f0480ab8f6906a1ecc9a8d5
		/* enforces zero-termination in sc_cont.param even if the string is larger */
		if (!arg_len && null_terminated /* NULL terminated argument like string */
			&& bpf_probe_read_str(sc_cont.param, PARAM_LEN, (void *)(arg)) < 0)
			sc_cont.failed = true;
		else if (sizeof(u8) <= arg_len && arg_len <= sizeof(u64) /* Conventional arguments like type (char, int, etc.) */
			&& bpf_probe_read(sc_cont.param, arg_len, (void *)(arg)))
			sc_cont.failed = true;
		else if (bpf_probe_read(sc_cont.param, PARAM_LEN, (void *)(arg))) /* TODO Struct arguments? */
			sc_cont.failed = true;

		bpf_debug_printk("Perf event output: sc_cont.index: %d; sizeof(sc_cont): %d\n", sc_cont.index, sizeof(sc_cont));
		bpf_perf_event_output(ctx, perf_buffer, BPF_F_CURRENT_CPU, &sc_cont, sizeof(sc_cont));
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
static inline int syscall_get_nr(struct pt_regs *regs)
{
#if defined(__TARGET_ARCH_arm64)
	return regs->syscallno;
#elif defined(__TARGET_ARCH_x86)
	return regs->orig_ax;
#else
#error "Traceloop was not ported to your architecture."
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
	u64 pid = bpf_get_current_pid_tgid();
	struct remembered_args *remembered;
	struct syscall_def_t *syscall_def;
	u64 ts = bpf_ktime_get_ns();
	struct task_struct *task;
	long ret = ctx->args[1];
	struct pt_regs *args;
	void *perf_buffer;
	u64 mntns_id;
	int i, r;
	int nr;

	r = bpf_map_update_elem(&regs_map, &pid, &empty, BPF_NOEXIST);
	if (r) {
		bpf_printk("exit: there should not be any pt_regs for key %lu: %d\n", pid, r);

		return 0;
	}

	args = bpf_map_lookup_elem(&regs_map, &pid);
	if (!args) {
		bpf_printk("exit: there should be a pt_regs for key %lu\n", pid);

		goto end;
	}

	bpf_probe_read(args, sizeof(*args), (void*) ctx->args[0]);
	nr = syscall_get_nr(args);
	/* TODO Why this can occur? */
	if (nr == -1)
		goto end;

	struct syscall_event_t sc = {
		.timestamp = bpf_ktime_get_ns(),
		.cpu = bpf_get_smp_processor_id(),
		.pid = pid,
		.typ = SYSCALL_EVENT_TYPE_EXIT,
		.id = nr,
	};
	sc.args[0] = ret;

	syscall_def = bpf_map_lookup_elem(&syscalls, &nr);
	if (syscall_def == NULL)
		syscall_def = &default_definition;

	task = (struct task_struct*)bpf_get_current_task();
	mntns_id = (u64) BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

	perf_buffer = bpf_map_lookup_elem(&map_of_perf_buffers, &mntns_id);
	if (!perf_buffer)
		goto end;

	remembered = bpf_map_lookup_elem(&probe_at_sys_exit, &pid);
	if (!remembered)
		goto end;

	for (i = 0; i < SYSCALL_ARGS; i++) {
		__u64 arg_len = syscall_def->args_len[i];

		if (!arg_len || !(arg_len & PARAM_PROBE_AT_EXIT_MASK))
			goto end_loop;

		bool null_terminated = false;
		struct syscall_event_cont_t sc_cont = {
			.timestamp = remembered->timestamp,
			.index = i,
			.failed = false,
		};

		arg_len &= ~PARAM_PROBE_AT_EXIT_MASK;

		if (arg_len == USE_RET_AS_PARAM_LENGTH) {
			if ((signed long) ret < 0)
				arg_len = 0;
			else
				arg_len = ret;
		} else if (arg_len == USE_NULL_BYTE_LENGTH) {
			null_terminated = true;
			arg_len = 0;
		} else if (arg_len >= USE_ARG_INDEX_AS_PARAM_LENGTH) {
			__u64 idx = arg_len & USE_ARG_INDEX_AS_PARAM_LENGTH_MASK;
			if (idx < SYSCALL_ARGS)
				arg_len = remembered->args[idx];
			else
				arg_len = PARAM_LEN;
		}

		if (arg_len > sizeof(sc_cont.param))
			arg_len = sizeof(sc_cont.param);

		if (null_terminated)
			sc_cont.length = USE_NULL_BYTE_LENGTH;
		else
			sc_cont.length = arg_len;

		// On Linux 4.14.137+, calling bpf_probe_read() with a variable size causes:
		// "invalid stack type R1 off=-304 access_size=0"
		// This is fixed on newer kernels.
		//
		// I know arg_len is not a volatile but that stops the compiler from
		// optimising the ifs into one bpf_probe_read call with a variable size.
		/* enforces zero-termination in sc_cont.param even if the string is larger */
		if (arg_len == 0
			&& null_terminated
			&& bpf_probe_read_str(sc_cont.param, PARAM_LEN, (void *)(remembered->args[i])) < 0)
			sc_cont.failed = true;
		else if (sizeof(u8) <= arg_len
			&& arg_len <= sizeof(u64)
			&& bpf_probe_read(sc_cont.param, arg_len, (void *)(remembered->args[i])))
			sc_cont.failed = true;
		else if (bpf_probe_read(sc_cont.param, PARAM_LEN, (void *)(remembered->args[i])))
			sc_cont.failed = true;

		bpf_debug_printk("Perf event output (exit): sc_cont.index: %d; sizeof(sc_cont): %d\n", sc_cont.index, sizeof(sc_cont));
		bpf_perf_event_output(ctx, perf_buffer, BPF_F_CURRENT_CPU, &sc_cont, sizeof(sc_cont));

end_loop:
		bpf_map_delete_elem(&probe_at_sys_exit, &pid);
	}

	bpf_get_current_comm(sc.comm, sizeof(sc.comm));

	bpf_debug_printk("Perf event output (exit): sc.id: %d; sc.comm: %s; sizeof(sc): %d\n", sc.id, sc.comm, sizeof(sc));
	bpf_perf_event_output(ctx, perf_buffer, BPF_F_CURRENT_CPU, &sc, sizeof(sc));

end:
	bpf_map_delete_elem(&regs_map, &pid);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
