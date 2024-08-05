// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024 The Inspektor Gadget authors */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/usdt_argument.h>

#define MAX_ENTRIES 1024
#define MAX_NAME_LEN 24

enum language {
	PYTHON,
	JAVA,
};

struct event {
	gadget_mntns_id mntns_id;
	enum language lang_raw;
	gadget_timestamp timestamp;
	u64 interval_ns;
	u32 pid;
	u32 tid;
	char comm[TASK_COMM_LEN];

	int py_generation;
	u64 py_n_objects;
	u64 java_start_used_bytes;
	u64 java_end_used_bytes;
};

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(gc, events, event);

/* used for context between uprobes and uretprobes */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // tid
	__type(value, u64); // timestamp
} start_time SEC(".maps");

struct python_storage_unit {
	int generation;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // tid
	__type(value, struct python_storage_unit);
} python_storage SEC(".maps");

struct java_storage_unit {
	u64 used_bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // tid
	__type(value, struct java_storage_unit);
} java_storage SEC(".maps");

// clean up the maps when a thread terminates, because there may be residual data in the map
// if a userspace thread is killed between uprobe and uretprobe
SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(void *ctx)
{
	u32 tid;

	tid = (u32)bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&start_time, &tid);
	bpf_map_delete_elem(&python_storage, &tid);
	bpf_map_delete_elem(&java_storage, &tid);
	return 0;
}

static __always_inline void record_start_time()
{
	u32 tid;
	u64 ts;

	tid = (u32)bpf_get_current_pid_tgid();
	ts = bpf_ktime_get_boot_ns();

	bpf_map_update_elem(&start_time, &tid, &ts, BPF_ANY);
}

SEC("usdt//usr/bin/python3:python:gc__start")
int trace_python_gc_begin(struct pt_regs *ctx)
{
	u32 tid;
	u64 *usdt_arg;
	struct python_storage_unit unit;

	if (gadget_should_discard_mntns_id(gadget_get_mntns_id()))
		return 0;

	// USDT prototype:
	// gc__start (int generation)
	// Introduced in https://github.com/python/cpython/commit/a785c87d6eacbed81543a8afe3cb098fabb9610a
	// See documentation: https://docs.python.org/3/howto/instrumentation.html
	usdt_arg = usdt_get_argument(ctx, 0);
	if (!usdt_arg)
		return 0;
	unit.generation = *usdt_arg;

	tid = (u32)bpf_get_current_pid_tgid();
	bpf_map_update_elem(&python_storage, &tid, &unit, BPF_ANY);

	record_start_time();

	return 0;
}

SEC("usdt/libjvm:hotspot:mem__pool__gc__begin")
int trace_java_gc_begin(struct pt_regs *ctx)
{
	u32 tid;
	u64 *usdt_arg;
	struct java_storage_unit unit;

	if (gadget_should_discard_mntns_id(gadget_get_mntns_id()))
		return 0;

	tid = (u32)bpf_get_current_pid_tgid();

	// USDT prototype:
	// mem__pool__gc__begin (char* manager_name, int manager_name_len,
	// 			 char* poll_name, int poll_name_len,
	//			 long initial_size, long memory_in_use,
	// 			 long committed_pages, long maximum_size)
	// See documentation: https://docs.oracle.com/javase/8/docs/technotes/guides/vm/dtrace.html
	usdt_arg = usdt_get_argument(ctx, 5); // memory_in_use
	if (!usdt_arg)
		return 0;
	unit.used_bytes = *usdt_arg;
	bpf_map_update_elem(&java_storage, &tid, &unit, BPF_ANY);

	record_start_time();

	return 0;
}

static __always_inline struct event *prepare_event_common()
{
	u64 mntns_id;
	u64 pid_tgid;
	u32 tid;
	u64 ts;
	u64 *tsp;
	struct event *event;

	mntns_id = gadget_get_mntns_id();
	if (gadget_should_discard_mntns_id(mntns_id))
		return NULL;

	ts = bpf_ktime_get_boot_ns();
	pid_tgid = bpf_get_current_pid_tgid();
	tid = (u32)pid_tgid;

	tsp = bpf_map_lookup_elem(&start_time, &tid);
	if (tsp == 0)
		return NULL;
	bpf_map_delete_elem(&start_time, &tid);

	event = gadget_reserve_buf(&events, sizeof(struct event));
	if (!event)
		return NULL;

	event->mntns_id = mntns_id;
	event->timestamp = ts;
	event->interval_ns = ts - *tsp;
	event->pid = pid_tgid >> 32;
	event->tid = tid;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	return event;
}

SEC("usdt//usr/bin/python3:python:gc__done")
int trace_python_gc_end(struct pt_regs *ctx)
{
	u64 *usdt_arg;
	u32 tid;
	struct python_storage_unit *unit;
	struct event *event;

	tid = (u32)bpf_get_current_pid_tgid();
	unit = bpf_map_lookup_elem(&python_storage, &tid);
	if (!unit)
		return 0;

	// USDT prototype:
	// gc__done (long collected)
	// Introduced in https://github.com/python/cpython/commit/a785c87d6eacbed81543a8afe3cb098fabb9610a
	// See documentation: https://docs.python.org/3/howto/instrumentation.html
	usdt_arg = usdt_get_argument(ctx, 0);
	if (!usdt_arg)
		return 0;

	event = prepare_event_common();
	if (!event)
		return 0;

	event->lang_raw = PYTHON;
	event->py_generation = unit->generation;
	event->py_n_objects = *usdt_arg;

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

SEC("usdt/libjvm:hotspot:mem__pool__gc__end")
int trace_java_gc_end(struct pt_regs *ctx)
{
	u64 mntns_id;
	u64 *usdt_arg;
	u32 tid;
	struct java_storage_unit *unit;
	struct event *event;

	mntns_id = gadget_get_mntns_id();
	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	tid = (u32)bpf_get_current_pid_tgid();
	unit = bpf_map_lookup_elem(&java_storage, &tid);
	if (!unit)
		return 0;

	// USDT prototype:
	// mem__pool__gc__end (	char* manager_name, int manager_name_len,
	// 			char* poll_name, int poll_name_len,
	//			long initial_size, long memory_in_use,
	// 			long committed_pages, long maximum_size)
	// See documentation: https://docs.oracle.com/javase/8/docs/technotes/guides/vm/dtrace.html
	usdt_arg = usdt_get_argument(ctx, 5); // memory_in_use
	if (!usdt_arg)
		return 0;

	event = prepare_event_common();
	if (!event)
		return 0;

	event->lang_raw = JAVA;
	event->java_start_used_bytes = unit->used_bytes;
	event->java_end_used_bytes = *usdt_arg;

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
