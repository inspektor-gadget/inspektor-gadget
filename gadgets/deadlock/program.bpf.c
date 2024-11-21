// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/macros.h>
#include <gadget/maps.bpf.h>
#include <gadget/mntns_filter.h>

#define MAX_HELD_MUTEXES 16
#define MAX_ENTRIES 65536
#define MAX_STACK_DEPTH 50

/* Stack map */
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
	__uint(max_entries, 256);
	__uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} stackmap SEC(".maps");

// Represents a mutex held by a thread.
struct held_mutex {
	u64 mutex;
	u64 stack_id;
};

// Represents an empty list of held mutexes.
static const struct held_mutex EMPTY_HELD_MUTEXES[MAX_HELD_MUTEXES] = {};

/* Map of thread ID to an array of held_mutex structs */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, gadget_tid);
	__type(value,
	       struct held_mutex[MAX_HELD_MUTEXES]); // array of held mutexes
} thread_to_held_mutexes SEC(".maps");

// Represents a dead process.
struct dead_pid {
	gadget_pid pid;
};

GADGET_TRACER_MAP(dead_pids, 1024 * 256);

// Key type for edges. Represents an edge from mutex1 to mutex2.
struct edges_key {
	__u64 mutex1;
	__u64 mutex2;
	gadget_pid pid;
};

// Value type for edges. Holds information about the edge.
struct edges_value {
	gadget_mntns_id mntns_id;

	gadget_tid tid;

	__u64 mutex1_stack_id;
	__u64 mutex2_stack_id;

	gadget_comm comm[TASK_COMM_LEN];
};

/* Map containing all edges in the mutex wait graph */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct edges_key);
	__type(value, struct edges_value);
} edges SEC(".maps");

const volatile pid_t targ_pid = 0;
GADGET_PARAM(targ_pid);

GADGET_MAPITER(mutex, edges);
GADGET_TRACER(process_exit, dead_pids, dead_pid);

/*
 * Creates edges in the mutex wait graph from each mutex
 * held by the current thread to the newly acquired mutex.
 */
static __always_inline int trace_mutex_acquire(struct pt_regs *ctx, u64 mutex)
{
	u64 mtns_id = gadget_get_mntns_id();
	if (gadget_should_discard_mntns_id(mtns_id))
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tid = (u32)pid_tgid;
	u32 pid = pid_tgid >> 32;

	/* filters */
	if (targ_pid && targ_pid != pid)
		return 0;

	struct held_mutex *held_mutexes = bpf_map_lookup_or_try_init(
		&thread_to_held_mutexes, &tid, &EMPTY_HELD_MUTEXES);
	if (!held_mutexes) {
		bpf_printk(
			"could not add thread_to_held_mutexes key. thread: %d, mutex: %p\n",
			tid, mutex);
		return 1; // out of memory
	}

// Check for recursive mutexes
#pragma unroll
	for (int i = 0; i < MAX_HELD_MUTEXES; ++i) {
		if (held_mutexes[i].mutex == mutex) {
			return 1; // disallow self edges
		}
	}
	u64 stack_id = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);

	// Add mutex to `held_mutexes` and update the graph
	int added_mutex =
		0; // flag indicating whether the mutex was added to `held_mutexes`
#pragma unroll
	for (int i = 0; i < MAX_HELD_MUTEXES; ++i) {
		if (!held_mutexes[i].mutex) {
			// Free slot found, add mutex if not already added
			if (!added_mutex) {
				held_mutexes[i].mutex = mutex;
				held_mutexes[i].stack_id = stack_id;
				added_mutex = 1; // update flag
			}
			continue;
		}
		// Add edges from held mutex to current mutex
		struct edges_key edge_key = {};
		edge_key.mutex1 = held_mutexes[i].mutex;
		edge_key.mutex2 = mutex;
		edge_key.pid = pid;

		struct edges_value edge_value = {};
		edge_value.tid = tid;
		edge_value.mntns_id = mtns_id;
		edge_value.mutex1_stack_id = held_mutexes[i].stack_id;
		edge_value.mutex2_stack_id = stack_id;
		bpf_get_current_comm(&edge_value.comm, sizeof(edge_value.comm));

		int result = bpf_map_update_elem(&edges, &edge_key, &edge_value,
						 BPF_ANY); // update graph
		if (result) {
			bpf_printk(
				"could not add edge key with mutexes %p and %p. error: %d\n",
				edge_key.mutex1, edge_key.mutex2, result);
			continue; // out of memory
		}
	}
	if (!added_mutex) {
		bpf_printk("could not add mutex %p\n", mutex);
		return 1; // no more free space on `held_mutexes`
	}
	return 0;
}

/*
 * Removes mutex from the list of held mutexes for the current thread.
 *
 * We don't remove the edges associated with the mutex from the mutex wait graph
 * as we are detecting "potential" deadlocks (even if they might never happen).
 *
 * If we remove the edges, we only detect deadlocks that actually happen during the trace.
 * But a deadlock that didn't happen during the trace could happen in the future
 * as it depends on factors such as thread scheduling and order of mutex acquisitions/releases.
 */
static __always_inline int trace_mutex_release(struct pt_regs *ctx, u64 mutex)
{
	if (gadget_should_discard_mntns_id(gadget_get_mntns_id()))
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tid = (u32)pid_tgid;
	u32 pid = pid_tgid >> 32;

	/* filters */
	if (targ_pid && targ_pid != pid)
		return 0;

	// Fetch the held mutexes for the current thread
	struct held_mutex *held_mutexes =
		bpf_map_lookup_elem(&thread_to_held_mutexes, &tid);
	if (!held_mutexes) {
		/*
         * If `held_mutexes` doesn't exist for the tid, then it means we either missed
         * the acquire event, or were out of memory when adding it.
         */
		bpf_printk(
			"could not find the thread's held mutexes. thread: %d, mutex: %p\n",
			tid, mutex);
		return 1;
	}

	int is_cleared =
		1; // flag indicating whether all held mutexes by the current thread are cleared
	for (int i = 0; i < MAX_HELD_MUTEXES; ++i) {
		// Find the current mutex and clear it
		if (held_mutexes[i].mutex == mutex) {
			held_mutexes[i].mutex = 0;
			held_mutexes[i].stack_id = 0;
		}
		if (held_mutexes[i].mutex != 0 && held_mutexes[i].mutex != 0) {
			// Thread still holds a mutex
			is_cleared = 0;
		}
	}
	if (is_cleared) {
		// Remove the entry from the map if no mutex is held by the thread
		bpf_map_delete_elem(&thread_to_held_mutexes, &tid);
	}
	return 0;
}

/*
 * Removes dead threads from BPF maps and
 * sends dead process IDs to userspace for clean-up
 */
static __always_inline int trace_process_exit(void *ctx)
{
	if (gadget_should_discard_mntns_id(gadget_get_mntns_id()))
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tid = (u32)pid_tgid;
	u32 pid = pid_tgid >> 32;

	/* filters */
	if (targ_pid && targ_pid != pid)
		return 0;

	bpf_map_delete_elem(&thread_to_held_mutexes, &tid);

	if (tid == pid) {
		// Process exited, send dead PID to userspace
		struct dead_pid *event;

		event = gadget_reserve_buf(&dead_pids, sizeof(*event));
		if (!event)
			return 0;

		event->pid = pid;

		gadget_submit_buf(ctx, &dead_pids, event, sizeof(*event));
	}
	return 0;
}

/* mutex acquisition */
SEC("uprobe/libc:pthread_mutex_lock")
int BPF_UPROBE(trace_uprobe_mutex_lock, void *mutex_addr)
{
	return trace_mutex_acquire(ctx, (u64)mutex_addr);
}

/* mutex release */
SEC("uprobe/libc:pthread_mutex_unlock")
int BPF_UPROBE(trace_uprobe_mutex_unlock, void *mutex_addr)
{
	return trace_mutex_release(ctx, (u64)mutex_addr);
}

/* process exit */
SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(void *ctx)
{
	return trace_process_exit(ctx);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";