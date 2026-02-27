// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/types.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/user_stack_map.h>

#define MAX_ENTRIES 10240

/* used for context between uprobes and uretprobes of allocations */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // tid
	__type(value, u64);
} sizes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct gadget_user_stack);
} tmp_gadget_user_stack SEC(".maps");

struct alloc_key {
	__u64 stack_id_key;
};

struct alloc_val {
	__u64 count;
	struct gadget_process proc;
	struct gadget_user_stack ustack_raw;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct alloc_key);
	__type(value, struct alloc_val);
} allocs SEC(".maps");

GADGET_MAPITER(allocs, allocs);

/**
 * clean up the maps when a thread terminates,
 * because there may be residual data in the map
 * if a userspace thread is killed between a uprobe and a uretprobe
 */
SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(void *ctx)
{
	u32 tid;

	tid = (u32)bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&sizes, &tid);
	return 0;
}

static __always_inline int gen_alloc_enter(size_t size)
{
	u32 tid;

	tid = (u32)bpf_get_current_pid_tgid();
	bpf_map_update_elem(&sizes, &tid, &size, BPF_ANY);

	return 0;
}

static __always_inline int gen_alloc_exit(struct pt_regs *ctx)
{
	u64 pid_tgid;
	u32 tid;
	u64 *size_ptr;
	u64 size;
	int ret;
	int zero = 0;

	pid_tgid = bpf_get_current_pid_tgid();
	tid = (u32)pid_tgid;
	size_ptr = bpf_map_lookup_elem(&sizes, &tid);
	if (!size_ptr)
		return 0;
	size = *size_ptr;
	bpf_map_delete_elem(&sizes, &tid);

	// Ignore failed allocations
	ret = PT_REGS_RC(ctx);
	if (ret == 0)
		return 0;

	if (gadget_should_discard_data_current())
		return 0;

	struct gadget_user_stack *ustack_raw = bpf_map_lookup_elem(&tmp_gadget_user_stack, &zero);
	if (ustack_raw == NULL)
		return 0;
	gadget_get_user_stack(ctx, ustack_raw);

	struct alloc_key key = {
		.stack_id_key = ustack_raw->otel_correlation_id,
	};

	struct alloc_val *val = bpf_map_lookup_elem(&allocs, &key);
	if (!val) {
		struct alloc_val new_val = {
			.count = size,
			.ustack_raw = *ustack_raw,
		};

		gadget_process_populate(&new_val.proc);

		bpf_map_update_elem(&allocs, &key, &new_val, BPF_ANY);
	} else {
		__sync_fetch_and_add(&val->count, size);
	}

	return 0;
}

SEC("uprobe//home/mauriciov/kinvolk/ebpf/inspektor-gadget/gadgets/ci/stacks/workload/libmylib.so:allocate_memory")
int BPF_UPROBE(trace_uprobe_alloc, size_t bytesize)
{
	bpf_printk("alloc enter: size=%lu", bytesize);
	return gen_alloc_enter(bytesize);
}

SEC("uretprobe//home/mauriciov/kinvolk/ebpf/inspektor-gadget/gadgets/ci/stacks/workload/libmylib.so:allocate_memory")
int trace_uretprobe_alloc(struct pt_regs *ctx)
{
	bpf_printk("alloc exit");
	return gen_alloc_exit(ctx);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
