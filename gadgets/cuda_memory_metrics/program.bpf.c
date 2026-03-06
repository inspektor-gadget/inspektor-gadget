// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/types.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>

#define MAX_ENTRIES 10240

/* Key for tracking allocations: must include PID because virtual addresses
 * are per-process (same pointer value in different processes = different memory).
 * Both fields are u64 to avoid struct padding — BPF hash maps compare keys
 * byte-by-byte, and padding bytes are not guaranteed to be zeroed. */
struct alloc_key {
	u64 pid;
	u64 ptr;
};

/* Track allocated pointers and their sizes for free tracking.
 * Separate maps per library: cudaMalloc internally calls cuMemAlloc_v2,
 * so both probes fire.  If cudart pools memory, cudaFree may not call
 * cuMemFree — each library must track its own pointer→size mapping
 * independently so the free path matches the right alloc.
 *
 * LRU hash: processes that exit without explicitly freeing allocations
 * (relying on cuCtxDestroy or OS cleanup) leave stale (pid, ptr)→size
 * entries behind.  BPF cannot iterate by partial key to clean them up
 * on process exit.  LRU eviction ensures stale entries from dead
 * processes are reclaimed when the map fills up, while live allocations
 * remain "recently used" and are kept. */

/* Per-pointer info stored in alloc_sizes maps: the allocation size
 * and whether it is host (pinned) or device (GPU) memory.  The free
 * path reads this to credit the correct gpu/host counter. */
struct alloc_info {
	u64 size;
	u8 is_host;
	u8 pad[7];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct alloc_key); // (pid, pointer)
	__type(value, struct alloc_info); // size + is_host
} libcuda_alloc_sizes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct alloc_key); // (pid, pointer)
	__type(value, struct alloc_info); // size + is_host
} cudart_alloc_sizes SEC(".maps");

/* Per-process outstanding bytes, split by memory type.
 * Incremented on alloc, decremented on free.  When a CUDA context is
 * destroyed (cuCtxDestroy), the driver bulk-frees all resources —
 * both device and page-locked host memory.  We use these counters to
 * credit the remaining bytes as implicitly freed.  The stats maps use
 * one shared mem_* counter set and distinguish memory class via
 * proc_key.host_raw (DEVICE = GPU/device, HOST = host/pinned). */
struct outstanding_info {
	u64 gpu;
	u64 host;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // pid
	__type(value, struct outstanding_info);
} libcuda_outstanding SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // pid
	__type(value, struct outstanding_info);
} cudart_outstanding SEC(".maps");

struct proc_mem_stats {
	gadget_mntns_id mntns_id;
	char comm[TASK_COMM_LEN];

	/* Memory counters for one memory class selected by proc_key.host_raw
	 * (host=0 => GPU/device memory, host=1 => host/pinned memory). */
	gadget_counter__u64 mem_alloc_bytes;
	gadget_counter__u64 mem_free_bytes;
	gadget_counter__u64 mem_alloc_calls;
	gadget_counter__u64 mem_free_calls;
	gadget_counter__u64 mem_implicit_free_bytes;
	gadget_counter__u64 mem_implicit_free_calls;
};

enum cuda_mem_type : u8 {
	CUDA_MEM_DEVICE,
	CUDA_MEM_HOST,
};

/* Key wrapper for stats maps (GADGET_MAPITER requires struct keys) */
struct proc_key {
	gadget_pid pid;
	enum cuda_mem_type
		host_raw; // DEVICE = GPU/device memory, HOST = host/pinned memory
	u8 pad[7];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct proc_key);
	__type(value, struct proc_mem_stats);
} libcuda_mem_stats SEC(".maps");

GADGET_MAPITER(libcuda_mem_stats, libcuda_mem_stats);

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct proc_key);
	__type(value, struct proc_mem_stats);
} libcudart_mem_stats SEC(".maps");

GADGET_MAPITER(libcudart_mem_stats, libcudart_mem_stats);

struct alloc_ctx {
	u64 size;
	u64 ptr_loc; // location where pointer will be stored (dptr argument)
	/* For cuMemAllocPitch: the driver picks a pitch >= WidthInBytes for
	 * alignment.  We store the pPitch output pointer and Height so the
	 * uretprobe can read the actual pitch and compute pitch * height.
	 * Zero for non-pitched allocations. */
	u64 pitch_loc;
	u64 height;
	u8 is_host; // 1 = host (pinned) memory, 0 = device (GPU) memory
};

/* Per-thread context maps for passing data from uprobe to uretprobe.
 * Keyed by TID (not PID) because multiple threads in the same process
 * can call CUDA alloc/free concurrently — PID keying would let one
 * thread's uprobe overwrite another's context before the uretprobe fires. */

/* libcuda.so uprobe/uretprobe context maps */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // tid
	__type(value, struct alloc_ctx);
} alloc_ctx_map SEC(".maps");

/* used for context between uprobes and uretprobes of frees */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // tid
	__type(value, u64); // pointer being freed
} free_ptrs SEC(".maps");

/* libcudart.so uprobe/uretprobe context maps.
 * Separate from libcuda maps because cudaMalloc internally calls
 * cuMemAlloc_v2 on the same thread — sharing context maps would
 * cause the nested uprobe to overwrite the outer context.
 * Also keyed by TID for the same concurrency reason as above. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // tid
	__type(value, struct alloc_ctx);
} cudart_alloc_ctx_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // tid
	__type(value, u64); // pointer being freed
} cudart_free_ptrs SEC(".maps");

/* ================================================================
 * Per-library stat-update helpers
 *
 * Each library (libcuda / libcudart) has its own stats map and
 * outstanding-bytes counter.
 *
 * Outstanding tracking (for implicit frees on cuCtxDestroy / process
 * exit) is handled separately in the alloc/free helpers rather than
 * inside update_stats(), because the outstanding counter is a single u64
 * aggregating both gpu and host bytes — it only needs to be adjusted
 * in the alloc/free paths, not in every counter-bump helper.
 * ================================================================ */
static __always_inline struct proc_mem_stats *
get_or_init_stats(void *stats_map, struct proc_key *pkey)
{
	struct proc_mem_stats *s;

	s = bpf_map_lookup_elem(stats_map, pkey);
	if (s)
		return s;

	struct proc_mem_stats ns = {};
	ns.mntns_id = gadget_get_current_mntns_id();
	bpf_get_current_comm(ns.comm, sizeof(ns.comm));
	bpf_map_update_elem(stats_map, pkey, &ns, BPF_ANY);

	return bpf_map_lookup_elem(stats_map, pkey);
}

enum stats_op {
	STATS_OP_ALLOC = 0,
	STATS_OP_FREE = 1,
	STATS_OP_IMPLICIT_FREE = 2,
};

static __always_inline void update_stats(void *stats_map, u32 pid, u8 host,
					 u64 size, enum stats_op op)
{
	struct proc_key pkey;
	__builtin_memset(&pkey, 0, sizeof(pkey));
	pkey.pid = pid;
	pkey.host_raw = host;
	struct proc_mem_stats *s = get_or_init_stats(stats_map, &pkey);

	if (!s)
		return;

	switch (op) {
	case STATS_OP_ALLOC:
		__sync_fetch_and_add(&s->mem_alloc_bytes, size);
		__sync_fetch_and_add(&s->mem_alloc_calls, 1);
		break;
	case STATS_OP_FREE:
		__sync_fetch_and_add(&s->mem_free_bytes, size);
		__sync_fetch_and_add(&s->mem_free_calls, 1);
		break;
	case STATS_OP_IMPLICIT_FREE:
		__sync_fetch_and_add(&s->mem_implicit_free_bytes, size);
		__sync_fetch_and_add(&s->mem_implicit_free_calls, 1);
		break;
	}
}

/* Outstanding-bytes helpers: adjust the per-pid outstanding counters.
 * Split into gpu and host fields so handle_ctx_destroy can credit
 * each implicit-free counter correctly. */
static __always_inline void outstanding_add(void *outstanding_map, u32 pid,
					    u64 size, u8 is_host)
{
	struct outstanding_info *oi;
	oi = bpf_map_lookup_elem(outstanding_map, &pid);
	if (oi) {
		if (is_host)
			__sync_fetch_and_add(&oi->host, size);
		else
			__sync_fetch_and_add(&oi->gpu, size);
	} else {
		struct outstanding_info noi = {};
		if (is_host)
			noi.host = size;
		else
			noi.gpu = size;
		bpf_map_update_elem(outstanding_map, &pid, &noi, BPF_ANY);
	}
}

static __always_inline void outstanding_sub(void *outstanding_map, u32 pid,
					    u64 size, u8 is_host)
{
	struct outstanding_info *oi;
	oi = bpf_map_lookup_elem(outstanding_map, &pid);
	if (!oi)
		return;
	u64 *field = is_host ? &oi->host : &oi->gpu;
	if (*field >= size)
		__sync_fetch_and_sub(field, size);
	else
		/* Atomic zero: clamp to 0 when free > outstanding
		 * (can happen due to races or missed allocs). */
		__sync_fetch_and_and(field, 0);
}

/* ================================================================
 * Generic alloc/free helpers
 *
 * Both libraries (libcuda / libcudart) share the same alloc/free
 * logic — only the BPF maps differ.  Each library keeps separate
 * per-thread context maps so that the nested driver-level uprobe
 * fired by cudaMalloc → cuMemAlloc_v2 does not clobber the runtime
 * context.  The generic helpers receive the right maps as void*.
 * ================================================================ */
static __always_inline int generic_alloc_enter(size_t size, void **ptr_loc,
					       size_t *pPitch, size_t Height,
					       u8 is_host, void *ctx_map)
{
	// Check the filter early: if discarded, skip storing context.
	// The exit probe will find no context and bail, keeping
	// alloc/free counts consistent (the alloc_sizes entry is never
	// created, so the corresponding free is naturally skipped).
	if (gadget_should_discard_data_current())
		return 0;

	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct alloc_ctx ctx = {};
	ctx.size = size;
	ctx.ptr_loc = (u64)ptr_loc;
	ctx.pitch_loc = (u64)pPitch;
	ctx.height = Height;
	ctx.is_host = is_host;
	bpf_map_update_elem(ctx_map, &tid, &ctx, BPF_ANY);
	return 0;
}

static __always_inline int generic_alloc_exit(int ret, void *ctx_map,
					      void *alloc_sizes_map,
					      void *outstanding_map,
					      void *stats_map)
{
	u64 pid_tgid;
	u32 pid;
	u32 tid;
	struct alloc_ctx *actx;
	u64 size;
	u64 ptr;
	u8 is_host;

	// Ignore failed allocations (CUDA_SUCCESS / cudaSuccess = 0)
	if (ret != 0)
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = (u32)(pid_tgid >> 32);
	tid = (u32)pid_tgid;

	actx = bpf_map_lookup_elem(ctx_map, &tid);
	if (!actx)
		return 0;

	// For pitched allocations, read the actual pitch chosen by the
	// driver/runtime and compute the real size.  For regular
	// allocations, pitch_loc is 0 and size was set in the uprobe.
	if (actx->pitch_loc) {
		u64 pitch;
		if (bpf_probe_read_user(&pitch, sizeof(pitch),
					(void *)actx->pitch_loc) < 0)
			goto end_delete_ctx;
		size = pitch * actx->height;
	} else {
		size = actx->size;
	}

	// Read the allocated pointer from user space
	if (bpf_probe_read_user(&ptr, sizeof(ptr), (void *)actx->ptr_loc) < 0)
		goto end_delete_ctx;
	is_host = actx->is_host;
	bpf_map_delete_elem(ctx_map, &tid);

	// Store (pid, pointer) → alloc_info mapping for free tracking.
	struct alloc_key akey = {};
	akey.pid = pid;
	akey.ptr = ptr;
	struct alloc_info ainfo;
	__builtin_memset(&ainfo, 0, sizeof(ainfo));
	ainfo.size = size;
	ainfo.is_host = is_host;
	bpf_map_update_elem(alloc_sizes_map, &akey, &ainfo, BPF_ANY);

	outstanding_add(outstanding_map, pid, size, is_host);

	update_stats(stats_map, pid, is_host, size, STATS_OP_ALLOC);

	return 0;

end_delete_ctx:
	bpf_map_delete_elem(ctx_map, &tid);
	return 0;
}

static __always_inline int generic_free_enter(u64 ptr, void *free_ptrs_map)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	bpf_map_update_elem(free_ptrs_map, &tid, &ptr, BPF_ANY);
	return 0;
}

static __always_inline int generic_free_exit(int ret, void *free_ptrs_map,
					     void *alloc_sizes_map,
					     void *outstanding_map,
					     void *stats_map)
{
	u64 pid_tgid;
	u32 pid;
	u32 tid;
	u64 *ptr_p;
	u64 ptr;

	// Ignore failed frees (CUDA_SUCCESS / cudaSuccess = 0)
	if (ret != 0)
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = (u32)(pid_tgid >> 32);
	tid = (u32)pid_tgid;

	// Always consume the free_ptrs entry first, regardless of
	// the discard filter.  Otherwise a discarded free leaks the
	// entry and the next free overwrites it, losing a free.
	ptr_p = bpf_map_lookup_elem(free_ptrs_map, &tid);
	if (!ptr_p)
		return 0;
	ptr = *ptr_p;
	bpf_map_delete_elem(free_ptrs_map, &tid);

	// cuMemFree(0) / cudaFree(NULL) is a valid no-op
	if (ptr == 0)
		return 0;

	// Lookup the alloc_info from our allocation tracking.
	// No filter check here: the alloc_sizes entry only exists if
	// the filter accepted the allocation, so the corresponding
	// free must always be counted.
	struct alloc_key akey = {};
	akey.pid = pid;
	akey.ptr = ptr;
	struct alloc_info *ainfo;
	ainfo = bpf_map_lookup_elem(alloc_sizes_map, &akey);
	if (!ainfo)
		return 0; // Unknown allocation or already consumed
	u64 size = ainfo->size;
	u8 is_host = ainfo->is_host;
	bpf_map_delete_elem(alloc_sizes_map, &akey);

	outstanding_sub(outstanding_map, pid, size, is_host);

	update_stats(stats_map, pid, is_host, size, STATS_OP_FREE);

	return 0;
}

/* ================================================================
 * CUDA context destroy & process exit
 * ================================================================ */

/*
 * When a CUDA context is destroyed, the driver bulk-frees all resources
 * associated with it — both device memory and page-locked host memory —
 * without calling cuMemFree/cuMemFreeHost for each allocation.  Credit
 * remaining outstanding bytes as implicitly freed, routing gpu and host
 * bytes to their respective counters, then delete the outstanding entry
 * so a subsequent CUDA context in the same process starts fresh.
 *
 * This is essential for applications like ollama that never explicitly
 * free individual allocations.
 */
static __always_inline void handle_ctx_destroy(u32 pid)
{
	struct outstanding_info *lc_oi;
	lc_oi = bpf_map_lookup_elem(&libcuda_outstanding, &pid);
	if (lc_oi) {
		if (lc_oi->gpu > 0)
			update_stats(&libcuda_mem_stats, pid, 0, lc_oi->gpu,
				     STATS_OP_IMPLICIT_FREE);
		if (lc_oi->host > 0)
			update_stats(&libcuda_mem_stats, pid, 1, lc_oi->host,
				     STATS_OP_IMPLICIT_FREE);
		bpf_map_delete_elem(&libcuda_outstanding, &pid);
	}

	struct outstanding_info *rt_oi;
	rt_oi = bpf_map_lookup_elem(&cudart_outstanding, &pid);
	if (rt_oi) {
		if (rt_oi->gpu > 0)
			update_stats(&libcudart_mem_stats, pid, 0, rt_oi->gpu,
				     STATS_OP_IMPLICIT_FREE);
		if (rt_oi->host > 0)
			update_stats(&libcudart_mem_stats, pid, 1, rt_oi->host,
				     STATS_OP_IMPLICIT_FREE);
		bpf_map_delete_elem(&cudart_outstanding, &pid);
	}
}

SEC("uretprobe/libcuda:cuCtxDestroy_v2")
int BPF_URETPROBE(trace_uretprobe_cuCtxDestroy_v2, int ret)
{
	if (ret != 0)
		return 0;

	u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
	handle_ctx_destroy(pid);
	return 0;
}

SEC("uretprobe/libcuda:cuCtxDestroy")
int BPF_URETPROBE(trace_uretprobe_cuCtxDestroy, int ret)
{
	if (ret != 0)
		return 0;

	u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
	handle_ctx_destroy(pid);
	return 0;
}

/* ================================================================
 * Process exit handler
 *
 * Cleans up per-thread transient maps.  When the main thread exits
 * (pid == tid), the process is dying — credit any remaining
 * outstanding CUDA bytes as implicitly freed.
 * ================================================================ */
SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(void *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = (u32)(pid_tgid >> 32);
	u32 tid = (u32)pid_tgid;

	// Clean up per-thread transient context maps.
	// Do NOT delete stats maps here: the per-process
	// counters must survive process exit so the gadget framework
	// can still read and report them.
	bpf_map_delete_elem(&alloc_ctx_map, &tid);
	bpf_map_delete_elem(&free_ptrs, &tid);
	bpf_map_delete_elem(&cudart_alloc_ctx_map, &tid);
	bpf_map_delete_elem(&cudart_free_ptrs, &tid);

	// Note: we intentionally do NOT clean up libcuda_alloc_sizes /
	// cudart_alloc_sizes here.  BPF cannot iterate by partial key
	// (pid) to delete matching entries.  These maps use LRU eviction
	// to reclaim stale entries from dead processes.

	if (pid == tid)
		handle_ctx_destroy(pid);

	return 0;
}

/* ================================================================
 * CUDA Driver API alloc/free uprobes (libcuda.so)
 * ================================================================ */
/*
 * cuMemAlloc - Allocate device memory (legacy, CUDA Driver API)
 * CUresult cuMemAlloc(CUdeviceptr *dptr, size_t bytesize)
 */
SEC("uprobe/libcuda:cuMemAlloc")
int BPF_UPROBE(trace_uprobe_cuMemAlloc, void **devptr, size_t bytesize)
{
	return generic_alloc_enter(bytesize, devptr, 0, 0, 0, &alloc_ctx_map);
}

SEC("uretprobe/libcuda:cuMemAlloc")
int BPF_URETPROBE(trace_uretprobe_cuMemAlloc, int ret)
{
	return generic_alloc_exit(ret, &alloc_ctx_map, &libcuda_alloc_sizes,
				  &libcuda_outstanding, &libcuda_mem_stats);
}

/*
 * cuMemAlloc_v2 - Allocate device memory (CUDA Driver API)
 * CUresult cuMemAlloc_v2(CUdeviceptr *dptr, size_t bytesize)
 */
SEC("uprobe/libcuda:cuMemAlloc_v2")
int BPF_UPROBE(trace_uprobe_cuMemAlloc_v2, void **dptr, size_t bytesize)
{
	return generic_alloc_enter(bytesize, dptr, 0, 0, 0, &alloc_ctx_map);
}

SEC("uretprobe/libcuda:cuMemAlloc_v2")
int BPF_URETPROBE(trace_uretprobe_cuMemAlloc_v2, int ret)
{
	return generic_alloc_exit(ret, &alloc_ctx_map, &libcuda_alloc_sizes,
				  &libcuda_outstanding, &libcuda_mem_stats);
}

/*
 * cuMemAllocHost_v2 - Allocate page-locked host memory (CUDA Driver API)
 * CUresult cuMemAllocHost_v2(void **pp, size_t bytesize)
 */
SEC("uprobe/libcuda:cuMemAllocHost_v2")
int BPF_UPROBE(trace_uprobe_cuMemAllocHost_v2, void **pp, size_t bytesize)
{
	return generic_alloc_enter(bytesize, pp, 0, 0, 1, &alloc_ctx_map);
}

SEC("uretprobe/libcuda:cuMemAllocHost_v2")
int BPF_URETPROBE(trace_uretprobe_cuMemAllocHost_v2, int ret)
{
	return generic_alloc_exit(ret, &alloc_ctx_map, &libcuda_alloc_sizes,
				  &libcuda_outstanding, &libcuda_mem_stats);
}

/*
 * cuMemAllocHost - Allocate page-locked host memory (legacy, CUDA Driver API)
 * CUresult cuMemAllocHost(void **pp, unsigned int bytesize)
 */
SEC("uprobe/libcuda:cuMemAllocHost")
int BPF_UPROBE(trace_uprobe_cuMemAllocHost, void **pp, unsigned int bytesize)
{
	return generic_alloc_enter((size_t)bytesize, pp, 0, 0, 1,
				   &alloc_ctx_map);
}

SEC("uretprobe/libcuda:cuMemAllocHost")
int BPF_URETPROBE(trace_uretprobe_cuMemAllocHost, int ret)
{
	return generic_alloc_exit(ret, &alloc_ctx_map, &libcuda_alloc_sizes,
				  &libcuda_outstanding, &libcuda_mem_stats);
}

/*
 * cuMemHostAlloc - Allocate page-locked host memory with flags (CUDA Driver API)
 * CUresult cuMemHostAlloc(void **pp, size_t bytesize, unsigned int Flags)
 *
 * Unlike cuMemAllocHost, this variant accepts allocation flags
 * (e.g. CU_MEMHOSTALLOC_PORTABLE, CU_MEMHOSTALLOC_DEVICEMAP).
 */
SEC("uprobe/libcuda:cuMemHostAlloc")
int BPF_UPROBE(trace_uprobe_cuMemHostAlloc, void **pp, size_t bytesize,
	       unsigned int Flags)
{
	return generic_alloc_enter(bytesize, pp, 0, 0, 1, &alloc_ctx_map);
}

SEC("uretprobe/libcuda:cuMemHostAlloc")
int BPF_URETPROBE(trace_uretprobe_cuMemHostAlloc, int ret)
{
	return generic_alloc_exit(ret, &alloc_ctx_map, &libcuda_alloc_sizes,
				  &libcuda_outstanding, &libcuda_mem_stats);
}

/*
 * cuMemAllocManaged - Allocate managed memory (CUDA Driver API)
 * CUresult cuMemAllocManaged(CUdeviceptr *dptr, size_t bytesize, unsigned int flags)
 */
SEC("uprobe/libcuda:cuMemAllocManaged")
int BPF_UPROBE(trace_uprobe_cuMemAllocManaged, void **dptr, size_t bytesize,
	       unsigned int flags)
{
	return generic_alloc_enter(bytesize, dptr, 0, 0, 0, &alloc_ctx_map);
}

SEC("uretprobe/libcuda:cuMemAllocManaged")
int BPF_URETPROBE(trace_uretprobe_cuMemAllocManaged, int ret)
{
	return generic_alloc_exit(ret, &alloc_ctx_map, &libcuda_alloc_sizes,
				  &libcuda_outstanding, &libcuda_mem_stats);
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
	return generic_alloc_enter(0, dptr, pPitch, Height, 0, &alloc_ctx_map);
}

SEC("uretprobe/libcuda:cuMemAllocPitch_v2")
int BPF_URETPROBE(trace_uretprobe_cuMemAllocPitch_v2, int ret)
{
	return generic_alloc_exit(ret, &alloc_ctx_map, &libcuda_alloc_sizes,
				  &libcuda_outstanding, &libcuda_mem_stats);
}

/*
 * cuMemAllocPitch - Allocate pitched device memory (legacy, CUDA Driver API)
 * CUresult cuMemAllocPitch(CUdeviceptr *dptr, size_t *pPitch, size_t WidthInBytes, size_t Height, unsigned int ElementSizeBytes)
 */
SEC("uprobe/libcuda:cuMemAllocPitch")
int BPF_UPROBE(trace_uprobe_cuMemAllocPitch, void **dptr, size_t *pPitch,
	       size_t WidthInBytes, size_t Height,
	       unsigned int ElementSizeBytes)
{
	return generic_alloc_enter(0, dptr, pPitch, Height, 0, &alloc_ctx_map);
}

SEC("uretprobe/libcuda:cuMemAllocPitch")
int BPF_URETPROBE(trace_uretprobe_cuMemAllocPitch, int ret)
{
	return generic_alloc_exit(ret, &alloc_ctx_map, &libcuda_alloc_sizes,
				  &libcuda_outstanding, &libcuda_mem_stats);
}

/*
 * cuMemAllocAsync - Allocate device memory asynchronously (CUDA Driver API)
 * CUresult cuMemAllocAsync(CUdeviceptr *dptr, size_t bytesize, CUstream hStream)
 */
SEC("uprobe/libcuda:cuMemAllocAsync")
int BPF_UPROBE(trace_uprobe_cuMemAllocAsync, void **dptr, size_t bytesize,
	       void *hStream)
{
	return generic_alloc_enter(bytesize, dptr, 0, 0, 0, &alloc_ctx_map);
}

SEC("uretprobe/libcuda:cuMemAllocAsync")
int BPF_URETPROBE(trace_uretprobe_cuMemAllocAsync, int ret)
{
	return generic_alloc_exit(ret, &alloc_ctx_map, &libcuda_alloc_sizes,
				  &libcuda_outstanding, &libcuda_mem_stats);
}

/*
 * cuMemAllocAsync_v2 - Allocate device memory asynchronously (CUDA 12.x Driver API)
 * CUresult cuMemAllocAsync_v2(CUdeviceptr *dptr, size_t bytesize, CUstream hStream)
 * Symbol only present in CUDA 12.x+ drivers; silently skipped otherwise.
 */
SEC("uprobe/libcuda:cuMemAllocAsync_v2")
int BPF_UPROBE(trace_uprobe_cuMemAllocAsync_v2, void **dptr, size_t bytesize,
	       void *hStream)
{
	return generic_alloc_enter(bytesize, dptr, 0, 0, 0, &alloc_ctx_map);
}

SEC("uretprobe/libcuda:cuMemAllocAsync_v2")
int BPF_URETPROBE(trace_uretprobe_cuMemAllocAsync_v2, int ret)
{
	return generic_alloc_exit(ret, &alloc_ctx_map, &libcuda_alloc_sizes,
				  &libcuda_outstanding, &libcuda_mem_stats);
}

/*
 * cuMemFree_v2 - Free device memory (CUDA Driver API)
 * CUresult cuMemFree_v2(CUdeviceptr dptr)
 */
SEC("uprobe/libcuda:cuMemFree_v2")
int BPF_UPROBE(trace_uprobe_cuMemFree_v2, u64 dptr)
{
	return generic_free_enter(dptr, &free_ptrs);
}

SEC("uretprobe/libcuda:cuMemFree_v2")
int BPF_URETPROBE(trace_uretprobe_cuMemFree_v2, int ret)
{
	return generic_free_exit(ret, &free_ptrs, &libcuda_alloc_sizes,
				 &libcuda_outstanding, &libcuda_mem_stats);
}

/*
 * cuMemFree - Free device memory (legacy, CUDA Driver API)
 * CUresult cuMemFree(CUdeviceptr dptr)
 */
SEC("uprobe/libcuda:cuMemFree")
int BPF_UPROBE(trace_uprobe_cuMemFree, u64 dptr)
{
	return generic_free_enter(dptr, &free_ptrs);
}

SEC("uretprobe/libcuda:cuMemFree")
int BPF_URETPROBE(trace_uretprobe_cuMemFree, int ret)
{
	return generic_free_exit(ret, &free_ptrs, &libcuda_alloc_sizes,
				 &libcuda_outstanding, &libcuda_mem_stats);
}

/*
 * cuMemFreeHost - Free page-locked host memory (CUDA Driver API)
 * CUresult cuMemFreeHost(void *p)
 */
SEC("uprobe/libcuda:cuMemFreeHost")
int BPF_UPROBE(trace_uprobe_cuMemFreeHost, u64 ptr)
{
	return generic_free_enter(ptr, &free_ptrs);
}

SEC("uretprobe/libcuda:cuMemFreeHost")
int BPF_URETPROBE(trace_uretprobe_cuMemFreeHost, int ret)
{
	return generic_free_exit(ret, &free_ptrs, &libcuda_alloc_sizes,
				 &libcuda_outstanding, &libcuda_mem_stats);
}

/*
 * cuMemFreeAsync - Free device memory asynchronously (CUDA Driver API)
 * CUresult cuMemFreeAsync(CUdeviceptr dptr, CUstream hStream)
 *
 * Note: async frees are stream-ordered — the GPU memory is not actually
 * reclaimed until the stream reaches this operation.  We credit the free
 * at CPU-call time (when the uretprobe fires), which may be earlier than
 * actual GPU-side reclamation.  This is acceptable for a metrics gadget
 * tracking API-level behaviour.
 */
SEC("uprobe/libcuda:cuMemFreeAsync")
int BPF_UPROBE(trace_uprobe_cuMemFreeAsync, u64 dptr, void *hStream)
{
	return generic_free_enter(dptr, &free_ptrs);
}

SEC("uretprobe/libcuda:cuMemFreeAsync")
int BPF_URETPROBE(trace_uretprobe_cuMemFreeAsync, int ret)
{
	return generic_free_exit(ret, &free_ptrs, &libcuda_alloc_sizes,
				 &libcuda_outstanding, &libcuda_mem_stats);
}

/*
 * cuMemFreeAsync_v2 - Free device memory asynchronously (CUDA 12.x Driver API)
 * CUresult cuMemFreeAsync_v2(CUdeviceptr dptr, CUstream hStream)
 * Symbol only present in CUDA 12.x+ drivers; silently skipped otherwise.
 */
SEC("uprobe/libcuda:cuMemFreeAsync_v2")
int BPF_UPROBE(trace_uprobe_cuMemFreeAsync_v2, u64 dptr, void *hStream)
{
	return generic_free_enter(dptr, &free_ptrs);
}

SEC("uretprobe/libcuda:cuMemFreeAsync_v2")
int BPF_URETPROBE(trace_uretprobe_cuMemFreeAsync_v2, int ret)
{
	return generic_free_exit(ret, &free_ptrs, &libcuda_alloc_sizes,
				 &libcuda_outstanding, &libcuda_mem_stats);
}

/* ================================================================
 * CUDA Runtime API alloc/free uprobes (libcudart.so)
 *
 * cudaMalloc et al. internally call the corresponding driver API
 * functions (cuMemAlloc_v2 etc.), so both the runtime and driver
 * probes fire for the same allocation.  Each library records into
 * its own stats map (libcuda_mem_stats vs libcudart_mem_stats)
 * and alloc-tracking map, so both views are independently correct.
 * Comparing the two reveals runtime-level pooling / caching.
 * ================================================================ */

/*
 * cudaMalloc - Allocate device memory (CUDA Runtime API)
 * cudaError_t cudaMalloc(void **devPtr, size_t size)
 */
SEC("uprobe/libcudart:cudaMalloc")
int BPF_UPROBE(trace_uprobe_cudaMalloc, void **devPtr, size_t size)
{
	return generic_alloc_enter(size, devPtr, 0, 0, 0,
				   &cudart_alloc_ctx_map);
}

SEC("uretprobe/libcudart:cudaMalloc")
int BPF_URETPROBE(trace_uretprobe_cudaMalloc, int ret)
{
	return generic_alloc_exit(ret, &cudart_alloc_ctx_map,
				  &cudart_alloc_sizes, &cudart_outstanding,
				  &libcudart_mem_stats);
}

/*
 * cudaMallocHost - Allocate page-locked host memory (CUDA Runtime API)
 * cudaError_t cudaMallocHost(void **ptr, size_t size)
 */
SEC("uprobe/libcudart:cudaMallocHost")
int BPF_UPROBE(trace_uprobe_cudaMallocHost, void **ptr, size_t size)
{
	return generic_alloc_enter(size, ptr, 0, 0, 1, &cudart_alloc_ctx_map);
}

SEC("uretprobe/libcudart:cudaMallocHost")
int BPF_URETPROBE(trace_uretprobe_cudaMallocHost, int ret)
{
	return generic_alloc_exit(ret, &cudart_alloc_ctx_map,
				  &cudart_alloc_sizes, &cudart_outstanding,
				  &libcudart_mem_stats);
}

/*
 * cudaHostAlloc - Allocate page-locked host memory with flags (CUDA Runtime API)
 * cudaError_t cudaHostAlloc(void **pHost, size_t size, unsigned int flags)
 *
 * Unlike cudaMallocHost, this variant accepts allocation flags
 * (e.g. cudaHostAllocPortable, cudaHostAllocMapped).
 */
SEC("uprobe/libcudart:cudaHostAlloc")
int BPF_UPROBE(trace_uprobe_cudaHostAlloc, void **pHost, size_t size,
	       unsigned int flags)
{
	return generic_alloc_enter(size, pHost, 0, 0, 1, &cudart_alloc_ctx_map);
}

SEC("uretprobe/libcudart:cudaHostAlloc")
int BPF_URETPROBE(trace_uretprobe_cudaHostAlloc, int ret)
{
	return generic_alloc_exit(ret, &cudart_alloc_ctx_map,
				  &cudart_alloc_sizes, &cudart_outstanding,
				  &libcudart_mem_stats);
}

/*
 * cudaMallocManaged - Allocate managed memory (CUDA Runtime API)
 * cudaError_t cudaMallocManaged(void **devPtr, size_t size, unsigned int flags)
 */
SEC("uprobe/libcudart:cudaMallocManaged")
int BPF_UPROBE(trace_uprobe_cudaMallocManaged, void **devPtr, size_t size,
	       unsigned int flags)
{
	return generic_alloc_enter(size, devPtr, 0, 0, 0,
				   &cudart_alloc_ctx_map);
}

SEC("uretprobe/libcudart:cudaMallocManaged")
int BPF_URETPROBE(trace_uretprobe_cudaMallocManaged, int ret)
{
	return generic_alloc_exit(ret, &cudart_alloc_ctx_map,
				  &cudart_alloc_sizes, &cudart_outstanding,
				  &libcudart_mem_stats);
}

/*
 * cudaMallocPitch - Allocate pitched device memory (CUDA Runtime API)
 * cudaError_t cudaMallocPitch(void **devPtr, size_t *pitch, size_t width,
 *                             size_t height)
 */
SEC("uprobe/libcudart:cudaMallocPitch")
int BPF_UPROBE(trace_uprobe_cudaMallocPitch, void **devPtr, size_t *pitch,
	       size_t width, size_t height)
{
	return generic_alloc_enter(0, devPtr, pitch, height, 0,
				   &cudart_alloc_ctx_map);
}

SEC("uretprobe/libcudart:cudaMallocPitch")
int BPF_URETPROBE(trace_uretprobe_cudaMallocPitch, int ret)
{
	return generic_alloc_exit(ret, &cudart_alloc_ctx_map,
				  &cudart_alloc_sizes, &cudart_outstanding,
				  &libcudart_mem_stats);
}

/*
 * cudaMallocAsync - Allocate device memory asynchronously (CUDA Runtime API)
 * cudaError_t cudaMallocAsync(void **devPtr, size_t size, cudaStream_t stream)
 */
SEC("uprobe/libcudart:cudaMallocAsync")
int BPF_UPROBE(trace_uprobe_cudaMallocAsync, void **devPtr, size_t size,
	       void *stream)
{
	return generic_alloc_enter(size, devPtr, 0, 0, 0,
				   &cudart_alloc_ctx_map);
}

SEC("uretprobe/libcudart:cudaMallocAsync")
int BPF_URETPROBE(trace_uretprobe_cudaMallocAsync, int ret)
{
	return generic_alloc_exit(ret, &cudart_alloc_ctx_map,
				  &cudart_alloc_sizes, &cudart_outstanding,
				  &libcudart_mem_stats);
}

/*
 * cudaFree - Free device memory (CUDA Runtime API)
 * cudaError_t cudaFree(void *devPtr)
 */
SEC("uprobe/libcudart:cudaFree")
int BPF_UPROBE(trace_uprobe_cudaFree, u64 devPtr)
{
	return generic_free_enter(devPtr, &cudart_free_ptrs);
}

SEC("uretprobe/libcudart:cudaFree")
int BPF_URETPROBE(trace_uretprobe_cudaFree, int ret)
{
	return generic_free_exit(ret, &cudart_free_ptrs, &cudart_alloc_sizes,
				 &cudart_outstanding, &libcudart_mem_stats);
}

/*
 * cudaFreeHost - Free page-locked host memory (CUDA Runtime API)
 * cudaError_t cudaFreeHost(void *ptr)
 */
SEC("uprobe/libcudart:cudaFreeHost")
int BPF_UPROBE(trace_uprobe_cudaFreeHost, u64 ptr)
{
	return generic_free_enter(ptr, &cudart_free_ptrs);
}

SEC("uretprobe/libcudart:cudaFreeHost")
int BPF_URETPROBE(trace_uretprobe_cudaFreeHost, int ret)
{
	return generic_free_exit(ret, &cudart_free_ptrs, &cudart_alloc_sizes,
				 &cudart_outstanding, &libcudart_mem_stats);
}

/*
 * cudaFreeAsync - Free device memory asynchronously (CUDA Runtime API)
 * cudaError_t cudaFreeAsync(void *devPtr, cudaStream_t stream)
 *
 * Note: async frees are stream-ordered — the GPU memory is not actually
 * reclaimed until the stream reaches this operation.  We credit the free
 * at CPU-call time (when the uretprobe fires), which may be earlier than
 * actual GPU-side reclamation.  This is acceptable for a metrics gadget
 * tracking API-level behaviour.
 */
SEC("uprobe/libcudart:cudaFreeAsync")
int BPF_UPROBE(trace_uprobe_cudaFreeAsync, u64 devPtr, void *stream)
{
	return generic_free_enter(devPtr, &cudart_free_ptrs);
}

SEC("uretprobe/libcudart:cudaFreeAsync")
int BPF_URETPROBE(trace_uretprobe_cudaFreeAsync, int ret)
{
	return generic_free_exit(ret, &cudart_free_ptrs, &cudart_alloc_sizes,
				 &cudart_outstanding, &libcudart_mem_stats);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";