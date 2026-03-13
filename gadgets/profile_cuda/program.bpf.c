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

enum memop {
	cuMemAlloc,
	cuMemFree,
	cuMemAllocHost,
	cuMemFreeHost,
	cuMemAllocManaged,
	cuMemAllocPitch,
	cuMemAlloc3D,
	cuMemAllocAsync,
	cuMemFreeAsync,
	cuMemPoolCreate,
};

/* used for context between uprobes and uretprobes of allocations */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // tid
	__type(value, u64);
} sizes SEC(".maps");

struct alloc_key {
	__u32 stack_id_key;
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

/*
 * Heap-allocated scratch space to avoid blowing the 256-byte stack limit
 * required for tail calls. struct alloc_val (~152 B) and
 * struct gadget_user_stack (~64 B) are too large to live on the BPF stack.
 */
struct heap_data {
	struct gadget_user_stack ustack;
	struct alloc_val val;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct heap_data);
} heap SEC(".maps");

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

static __always_inline int gen_alloc_exit(struct pt_regs *ctx,
					  enum memop operation)
{
	u64 pid_tgid;
	u32 tid;
	u64 *size_ptr;
	u64 size;
	int ret;

	// Ignore failed allocations (CUDA_SUCCESS = 0)
	ret = PT_REGS_RC(ctx);
	if (ret != 0)
		return 0;

	if (gadget_should_discard_data_current())
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	tid = (u32)pid_tgid;
	size_ptr = bpf_map_lookup_elem(&sizes, &tid);
	if (!size_ptr)
		return 0;
	size = *size_ptr;
	bpf_map_delete_elem(&sizes, &tid);

	/*
	 * Use a per-CPU array as heap space for the large structs that would
	 * otherwise push the stack frame well beyond the 256-byte limit
	 * enforced by the verifier when tail calls are reachable.
	 */
	u32 zero = 0;
	struct heap_data *heap_ptr = bpf_map_lookup_elem(&heap, &zero);
	if (!heap_ptr)
		return 0;

	gadget_get_user_stack(ctx, &heap_ptr->ustack);

	struct alloc_key key = {
		.stack_id_key = heap_ptr->ustack.stack_id,
	};

	struct alloc_val *val = bpf_map_lookup_elem(&allocs, &key);
	if (!val) {
		__builtin_memset(&heap_ptr->val, 0, sizeof(heap_ptr->val));
		heap_ptr->val.count = size;
		heap_ptr->val.ustack_raw = heap_ptr->ustack;

		gadget_process_populate(&heap_ptr->val.proc);

		bpf_map_update_elem(&allocs, &key, &heap_ptr->val,
				    BPF_NOEXIST);
	} else {
		__sync_fetch_and_add(&val->count, size);
	}

	return 0;
}

/*
 * cuMemAlloc_v2 - Allocate device memory (CUDA Driver API)
 * CUresult cuMemAlloc_v2(CUdeviceptr *dptr, size_t bytesize)
 */
SEC("uprobe/libcuda:cuMemAlloc_v2")
int BPF_UPROBE(trace_uprobe_cuMemAlloc_v2, void **dptr, size_t bytesize)
{
	return gen_alloc_enter(bytesize);
}

SEC("uretprobe/libcuda:cuMemAlloc_v2")
int trace_uretprobe_cuMemAlloc_v2(struct pt_regs *ctx)
{
	return gen_alloc_exit(ctx, cuMemAlloc);
}

/*
 * cuMemAllocHost_v2 - Allocate page-locked host memory (CUDA Driver API)
 * CUresult cuMemAllocHost_v2(void **pp, size_t bytesize)
 */
SEC("uprobe/libcuda:cuMemAllocHost_v2")
int BPF_UPROBE(trace_uprobe_cuMemAllocHost_v2, void **pp, size_t bytesize)
{
	return gen_alloc_enter(bytesize);
}

SEC("uretprobe/libcuda:cuMemAllocHost_v2")
int trace_uretprobe_cuMemAllocHost_v2(struct pt_regs *ctx)
{
	return gen_alloc_exit(ctx, cuMemAllocHost);
}

/*
 * cuMemAllocManaged - Allocate managed memory (CUDA Driver API)
 * CUresult cuMemAllocManaged(CUdeviceptr *dptr, size_t bytesize, unsigned int flags)
 */
SEC("uprobe/libcuda:cuMemAllocManaged")
int BPF_UPROBE(trace_uprobe_cuMemAllocManaged, void **dptr, size_t bytesize,
	       unsigned int flags)
{
	return gen_alloc_enter(bytesize);
}

SEC("uretprobe/libcuda:cuMemAllocManaged")
int trace_uretprobe_cuMemAllocManaged(struct pt_regs *ctx)
{
	return gen_alloc_exit(ctx, cuMemAllocManaged);
}

/*
 * cuMemAllocPitch_v2 - Allocate pitched device memory (CUDA Driver API)
 * CUresult cuMemAllocPitch_v2(CUdeviceptr *dptr, size_t *pPitch, size_t WidthInBytes, size_t Height, unsigned int ElementSizeBytes)
 */
SEC("uprobe/libcuda:cuMemAllocPitch_v2")
int BPF_UPROBE(trace_uprobe_cuMemAllocPitch_v2, void **dptr, size_t *pPitch,
	       size_t WidthInBytes, size_t Height,
	       unsigned int ElementSizeBytes)
{
	size_t size = WidthInBytes * Height; // Approximate size
	return gen_alloc_enter(size);
}

SEC("uretprobe/libcuda:cuMemAllocPitch_v2")
int trace_uretprobe_cuMemAllocPitch_v2(struct pt_regs *ctx)
{
	return gen_alloc_exit(ctx, cuMemAllocPitch);
}

/*
 * cuMemAllocAsync - Allocate device memory asynchronously (CUDA Driver API)
 * CUresult cuMemAllocAsync(CUdeviceptr *dptr, size_t bytesize, CUstream hStream)
 *
 * Used heavily by PyTorch caching allocator, TensorFlow, and RAPIDS.
 * The allocation is enqueued on the stream and may be fulfilled from a
 * memory pool, but the requested size is the meaningful metric to profile.
 */
SEC("uprobe/libcuda:cuMemAllocAsync")
int BPF_UPROBE(trace_uprobe_cuMemAllocAsync, void **dptr, size_t bytesize,
	       void *hStream)
{
	return gen_alloc_enter(bytesize);
}

SEC("uretprobe/libcuda:cuMemAllocAsync")
int trace_uretprobe_cuMemAllocAsync(struct pt_regs *ctx)
{
	return gen_alloc_exit(ctx, cuMemAllocAsync);
}

/*
 * cuMemFreeAsync - Free device memory asynchronously (CUDA Driver API)
 * CUresult cuMemFreeAsync(CUdeviceptr dptr, CUstream hStream)
 *
 * The freed pointer is returned to the memory pool.  We track the call
 * count (size=1 per call) so the profile shows how frequently async
 * frees happen and from which call-stacks.
 */
SEC("uprobe/libcuda:cuMemFreeAsync")
int BPF_UPROBE(trace_uprobe_cuMemFreeAsync, void *dptr, void *hStream)
{
	/* No byte-size argument; record 1 to count invocations. */
	return gen_alloc_enter(1);
}

SEC("uretprobe/libcuda:cuMemFreeAsync")
int trace_uretprobe_cuMemFreeAsync(struct pt_regs *ctx)
{
	return gen_alloc_exit(ctx, cuMemFreeAsync);
}

/*
 * cuMemPoolCreate - Create a memory pool (CUDA Driver API)
 * CUresult cuMemPoolCreate(CUmemoryPool *pool, const CUmemPoolProps *poolProps)
 *
 * Tracks pool creation events. Size=1 per call (no byte-size parameter).
 * Useful for understanding when and how many memory pools are created,
 * especially in multi-GPU or complex ML workloads.
 */
SEC("uprobe/libcuda:cuMemPoolCreate")
int BPF_UPROBE(trace_uprobe_cuMemPoolCreate, void *pool, void *poolProps)
{
	/* No byte-size argument; record 1 to count pool creations. */
	return gen_alloc_enter(1);
}

SEC("uretprobe/libcuda:cuMemPoolCreate")
int trace_uretprobe_cuMemPoolCreate(struct pt_regs *ctx)
{
	return gen_alloc_exit(ctx, cuMemPoolCreate);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
