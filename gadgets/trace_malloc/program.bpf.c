// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>

#define MAX_ENTRIES 10240

enum memop {
	malloc,
	free,
	calloc,
	realloc,
	realloc_free,
	mmap,
	munmap,
	posix_memalign,
	aligned_alloc,
	valloc,
	memalign,
	pvalloc,
};

struct event {
	gadget_timestamp timestamp_raw;
	gadget_mntns_id mntns_id;

	gadget_comm comm[TASK_COMM_LEN];
	// user-space terminology for pid and tid
	gadget_pid pid;
	gadget_tid tid;
	gadget_uid uid;
	gadget_gid gid;

	enum memop operation_raw;
	__u64 addr;
	__u64 size;
};

/* used for context between uprobes and uretprobes of allocations */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // tid
	__type(value, u64);
} sizes SEC(".maps");

/* used by posix_memalign */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // tid
	__type(value, u64);
} memptrs SEC(".maps");

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
	bpf_map_delete_elem(&memptrs, &tid);
	return 0;
}

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(malloc, events, event);

static __always_inline int gen_alloc_enter(size_t size)
{
	u32 tid;

	tid = (u32)bpf_get_current_pid_tgid();
	bpf_map_update_elem(&sizes, &tid, &size, BPF_ANY);

	return 0;
}

static __always_inline int gen_alloc_exit(struct pt_regs *ctx,
					  enum memop operation, u64 addr)
{
	u64 mntns_id;
	struct event *event;
	u64 pid_tgid;
	u32 tid;
	u64 *size_ptr;
	u64 size;
	u64 uid_gid;

	mntns_id = gadget_get_mntns_id();
	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	tid = (u32)pid_tgid;
	size_ptr = bpf_map_lookup_elem(&sizes, &tid);
	if (!size_ptr)
		return 0;
	size = *size_ptr;
	bpf_map_delete_elem(&sizes, &tid);

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	uid_gid = bpf_get_current_uid_gid();

	event->mntns_id = mntns_id;
	event->pid = pid_tgid >> 32;
	event->tid = tid;
	event->uid = uid_gid;
	event->gid = uid_gid >> 32;
	bpf_get_current_comm(event->comm, sizeof(event->comm));
	event->operation_raw = operation;
	event->addr = addr;
	event->size = size;
	event->timestamp_raw = bpf_ktime_get_ns();

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

static __always_inline int gen_free_enter(struct pt_regs *ctx,
					  enum memop operation, u64 addr)
{
	u64 mntns_id;
	struct event *event;
	u64 pid_tgid;
	u32 tid;

	mntns_id = gadget_get_mntns_id();
	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	tid = (u32)pid_tgid;

	event->mntns_id = mntns_id;
	event->pid = pid_tgid >> 32;
	event->tid = tid;
	bpf_get_current_comm(event->comm, sizeof(event->comm));
	event->operation_raw = operation;
	event->addr = addr;
	event->size = 0;
	event->timestamp_raw = bpf_ktime_get_ns();

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

/* common macros */
#define PROBE_RET_VAL_FOR_ALLOC(func)                              \
	SEC("uretprobe/libc:" #func)                               \
	int trace_uretprobe_##func(struct pt_regs *ctx)            \
	{                                                          \
		return gen_alloc_exit(ctx, func, PT_REGS_RC(ctx)); \
	}

/* malloc */
SEC("uprobe/libc:malloc")
int BPF_UPROBE(trace_uprobe_malloc, size_t size)
{
	return gen_alloc_enter(size);
}

PROBE_RET_VAL_FOR_ALLOC(malloc)

/* free */
SEC("uprobe/libc:free")
int BPF_UPROBE(trace_uprobe_free, void *address)
{
	return gen_free_enter(ctx, free, (u64)address);
}

/* calloc */
SEC("uprobe/libc:calloc")
int BPF_UPROBE(trace_uprobe_calloc, size_t nmemb, size_t size)
{
	return gen_alloc_enter(nmemb * size);
}

PROBE_RET_VAL_FOR_ALLOC(calloc)

/* realloc */
SEC("uprobe/libc:realloc")
int BPF_UPROBE(trace_uprobe_realloc, void *ptr, size_t size)
{
	gen_free_enter(ctx, realloc_free, (u64)ptr);
	return gen_alloc_enter(size);
}

PROBE_RET_VAL_FOR_ALLOC(realloc)

/* mmap */
SEC("uprobe/libc:mmap")
int BPF_UPROBE(trace_uprobe_mmap, void *address, size_t size)
{
	return gen_alloc_enter(size);
}

PROBE_RET_VAL_FOR_ALLOC(mmap)

/* munmap */
SEC("uprobe/libc:munmap")
int BPF_UPROBE(trace_uprobe_munmap, void *address)
{
	return gen_free_enter(ctx, munmap, (u64)address);
}

/* posix_memalign */
SEC("uprobe/libc:posix_memalign")
int BPF_UPROBE(trace_uprobe_posix_memalign, void **memptr, size_t alignment,
	       size_t size)
{
	u64 memptr64;
	u32 tid;

	tid = (u32)bpf_get_current_pid_tgid();
	memptr64 = (u64)memptr;
	bpf_map_update_elem(&memptrs, &tid, &memptr64, BPF_ANY);

	return gen_alloc_enter(size);
}

SEC("uretprobe/libc:posix_memalign")
int trace_uretprobe_posix_memalign(struct pt_regs *ctx)
{
	u64 *memptr64;
	void *addr;
	u32 tid;

	tid = (u32)bpf_get_current_pid_tgid();

	memptr64 = bpf_map_lookup_elem(&memptrs, &tid);
	if (!memptr64)
		return 0;
	bpf_map_delete_elem(&memptrs, &tid);

	if (bpf_probe_read_user(&addr, sizeof(void *), (void *)*memptr64))
		return 0;

	return gen_alloc_exit(ctx, posix_memalign, (u64)addr);
}

/* aligned_alloc */
SEC("uprobe/libc:aligned_alloc")
int BPF_UPROBE(trace_uprobe_aligned_alloc, size_t alignment, size_t size)
{
	return gen_alloc_enter(size);
}

PROBE_RET_VAL_FOR_ALLOC(aligned_alloc)

/* valloc */
SEC("uprobe/libc:valloc")
int BPF_UPROBE(trace_uprobe_valloc, size_t size)
{
	return gen_alloc_enter(size);
}

PROBE_RET_VAL_FOR_ALLOC(valloc)

/* memalign */
SEC("uprobe/libc:memalign")
int BPF_UPROBE(trace_uprobe_memalign, size_t alignment, size_t size)
{
	return gen_alloc_enter(size);
}

PROBE_RET_VAL_FOR_ALLOC(memalign)

/* pvalloc */
SEC("uprobe/libc:pvalloc")
int BPF_UPROBE(trace_uprobe_pvalloc, size_t size)
{
	return gen_alloc_enter(size);
}

PROBE_RET_VAL_FOR_ALLOC(pvalloc)

char LICENSE[] SEC("license") = "Dual BSD/GPL";
