// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/filesystem.h>
#include <gadget/kernel_stack_map.h>
#include <gadget/user_stack_map.h>

SEC("tracepoint/tail/tail_f0")
int tail_f0()
{
	bpf_printk("tail_f0 called");
	return 0;
}

SEC("tracepoint/tail/tail_f1")
int tail_f1()
{
	bpf_printk("tail_f1 called");
	return 0;
}

SEC("kprobe/tail_kprobe_f0")
int tail_kprobe_f0()
{
	bpf_printk("tail_kprobe_f0 called");
	return 0;
}

SEC("kprobe/tail_kprobe_f1")
int tail_kprobe_f1()
{
	bpf_printk("tail_kprobe_f1 called");
	return 0;
}


// SEC("freplace/subprog") int replacement_func0() {
// 	bpf_printk("replacement_func0 called");
// 	return 0;
// }

// prog array for tail calls
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 4);
	__type(key, u32);
	__type(value, u32);
	__array(values, int());
} tail_calls SEC(".maps") = {
	.values = {
        [0] = &tail_f0,
        [1] = &tail_f1,
    },
};
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 4);
	__type(key, u32);
	__type(value, u32);
	__array(values, int());
} tail_calls_kprobe SEC(".maps") = {
	.values = {
        [0] = &tail_kprobe_f0,
        [1] = &tail_kprobe_f1,
    },
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, u64);
} otel_ebpf_profiler_context SEC(".maps");

struct generic_param {
  u64 correlation_id;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct generic_param);
} otel_generic_params SEC(".maps");

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;
	gadget_kernel_stack kstack_raw;
	struct gadget_user_stack ustack;
	u64 otel_correlation_id;
};

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(exec, events, event);

const volatile bool collect_kstack = true;
GADGET_PARAM(collect_kstack);

static __attribute__((noinline)) int subprog(struct trace_event_raw_sched_process_exec *ctx) {
    bpf_printk("subprog called");    
	u32 key = 0;
	bpf_tail_call(ctx, &tail_calls, key);
    return 0;
}

static __attribute__((noinline)) int call_otel_ebpf_profiler(void *ctx) {
    bpf_printk("call_otel_ebpf_profiler called. Calling otel-ebpf-profiler's kprobe_unwind_native!");

	u32 key = 2; // Entry set by the ebpf operator (hardcoded for now...)
	bpf_tail_call(ctx, &tail_calls_kprobe, key);
    return 0;
}

// tracepoint/sched/sched_process_exec is called after a successful execve
SEC("tracepoint/sched/sched_process_exec")
int ig_sched_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	return 0;
	/////////
	u32 pre_sched_pid = ctx->old_pid;
	struct event *event;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);

	bpf_printk("execve: parent=%d oldpid=%d newpid=%d",
		   BPF_CORE_READ(parent, tgid), pre_sched_pid,
		   BPF_CORE_READ(task, tgid));

	event = gadget_reserve_buf(&events, sizeof(struct event));
	if (!event)
		return 0;

	gadget_process_populate(&event->proc);
	event->timestamp_raw = bpf_ktime_get_boot_ns();
	if (collect_kstack)
		event->kstack_raw = gadget_get_kernel_stack(ctx);
	gadget_get_user_stack(ctx, &event->ustack);

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	bpf_printk("tracepoint: step 1");
	subprog(ctx);
	bpf_printk("tracepoint: step 2");

	u32 key = 1;
	bpf_tail_call(ctx, &tail_calls, key);

	return 0;
}

SEC("kprobe/cap_capable")
int BPF_KPROBE(ig_trace_cap_e, const struct cred *cred,
               struct user_namespace *targ_ns, int cap, int cap_opt)
{
	u64 ts = bpf_ktime_get_boot_ns();
	struct event *event;

	if (gadget_should_discard_data_current())
		return 0;

	struct generic_param param = {
		.correlation_id = ts,
	};
	u32 zero = 0;
	if (bpf_map_update_elem(&otel_generic_params, &zero, &param, BPF_ANY) < 0) {
		return 0;
	}

	bpf_printk("kprobe/cap_capable: Before calling otel");
	call_otel_ebpf_profiler(ctx);
	bpf_printk("kprobe/cap_capable: After calling otel");

	event = gadget_reserve_buf(&events, sizeof(struct event));
	if (!event)
		return 0;

	gadget_process_populate(&event->proc);
	event->timestamp_raw = ts;
	if (collect_kstack)
		event->kstack_raw = gadget_get_kernel_stack(ctx);
	gadget_get_user_stack(ctx, &event->ustack);

	event->otel_correlation_id = ts;

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	u32 key = 1;
	bpf_tail_call(ctx, &tail_calls_kprobe, key);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
