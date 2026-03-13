// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/types.h>
#include <gadget/buffer.h>
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

/* ── Inference phase state machine ─────────────────────────────── */
enum inference_phase {
	PHASE_IDLE = 0,
	PHASE_PREFILL = 1,
	PHASE_DECODE = 2,
};

/* Per-process inference tracking state */
struct inference_state {
	enum inference_phase phase;

	/* Prefill tracking */
	__u64 prefill_start_ns;
	__u64 last_activity_ns;
	__u32 prefill_kernel_count;

	/* Decode tracking */
	__u64 decode_start_ns;
	__u64 last_token_ns;
	__u32 decode_token_count;

	/* CUDA Graph capture filtering */
	__u8 in_graph_capture;

	/* Request counting */
	__u64 first_request_ns;
	__u32 completed_requests;
};

/* ── Event structures ──────────────────────────────────────────── */

/* TTFT event: emitted at prefill->decode transition */
struct ttft_event {
	struct gadget_process proc;
	__u64 ttft_ns;
	__u32 prefill_kernels;
	__u64 prefill_start;
	__u64 prefill_end;
};

/* Inference summary: emitted when decode completes */
struct inference_event {
	struct gadget_process proc;
	__u64 ttft_ns;
	__u64 e2el_ns;
	__u64 tgt_ns;
	__u64 avg_tpot_ns;
	__u64 avg_itl_ns;
	__u32 output_tokens;
	__u32 prefill_kernels;
	__u32 completed_reqs;
	__u64 tokens_per_sec;
	__u64 wall_time_ns;
};

/* ITL event: emitted per-token during decode */
struct itl_event {
	struct gadget_process proc;
	__u64 itl_ns;
	__u32 token_index;
};

/* ── Configurable parameters ───────────────────────────────────── */

const volatile __u64 gap_threshold_ns = 200000; /* 200us */
GADGET_PARAM(gap_threshold_ns);

const volatile __u32 min_prefill_kernels = 10;
GADGET_PARAM(min_prefill_kernels);

const volatile __u64 cooldown_ns = 100000000; /* 100ms */
GADGET_PARAM(cooldown_ns);

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

/* Inference state: per-process */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, struct inference_state);
} inference_states SEC(".maps");

/* Event output buffers */
GADGET_TRACER_MAP(ttft_events, 262144);
GADGET_TRACER(ttft, ttft_events, ttft_event);

GADGET_TRACER_MAP(inference_events, 262144);
GADGET_TRACER(inference, inference_events, inference_event);

GADGET_TRACER_MAP(itl_events, 262144);
GADGET_TRACER(itl, itl_events, itl_event);


/**
 * clean up the maps when a thread terminates,
 * because there may be residual data in the map
 * if a userspace thread is killed between a uprobe and a uretprobe
 */
/* ── Inference metric helpers ───────────────────────────────────── */

/*
 * Check if we should transition DECODE -> IDLE and emit summary.
 * Called when activity arrives with a gap > cooldown_ns.
 */
static __always_inline void
maybe_complete_inference(void *ctx, struct inference_state *state, __u32 tgid,
			 __u64 now)
{
	if (state->phase != PHASE_DECODE)
		return;

	__u64 gap = now - state->last_activity_ns;
	if (gap <= cooldown_ns)
		return;

	/* DECODE -> IDLE: emit inference summary */
	state->completed_requests++;

	struct inference_event *event;
	event = gadget_reserve_buf(&inference_events, sizeof(*event));
	if (event) {
		__builtin_memset(event, 0, sizeof(*event));
		gadget_process_populate(&event->proc);

		__u64 ttft = 0;
		if (state->decode_start_ns > state->prefill_start_ns)
			ttft = state->decode_start_ns - state->prefill_start_ns;

		__u64 e2el = state->last_activity_ns - state->prefill_start_ns;
		__u64 tgt = 0;
		if (state->last_activity_ns > state->decode_start_ns)
			tgt = state->last_activity_ns - state->decode_start_ns;

		event->ttft_ns = ttft;
		event->e2el_ns = e2el;
		event->tgt_ns = tgt;
		event->output_tokens = state->decode_token_count;
		event->prefill_kernels = state->prefill_kernel_count;
		event->completed_reqs = state->completed_requests;

		/* TPOT: tgt / (tokens - 1), avoid div by 0 */
		if (state->decode_token_count > 1)
			event->avg_tpot_ns = tgt / (state->decode_token_count - 1);
		else if (state->decode_token_count == 1)
			event->avg_tpot_ns = tgt;

		event->avg_itl_ns = event->avg_tpot_ns;

		/* Tokens/sec * 1000 (milli-tokens/sec for precision) */
		if (tgt > 0)
			event->tokens_per_sec =
				(__u64)state->decode_token_count * 1000000000ULL * 1000ULL / tgt;

		if (state->first_request_ns > 0)
			event->wall_time_ns = now - state->first_request_ns;

		gadget_submit_buf(ctx, &inference_events, event, sizeof(*event));
	}

	state->phase = PHASE_IDLE;
}

/*
 * Core kernel launch handler — drives IDLE->PREFILL->DECODE->IDLE.
 * Shared by cuLaunchKernel and cuLaunchKernelEx.
 */
static __always_inline int handle_kernel_launch(void *ctx)
{
	u64 pid_tgid;
	u32 tgid;
	u64 now;
	struct inference_state *state;
	struct inference_state new_state = {};

	if (gadget_should_discard_data_current())
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	tgid = (u32)(pid_tgid >> 32);
	now = bpf_ktime_get_ns();

	state = bpf_map_lookup_elem(&inference_states, &tgid);

	if (!state) {
		new_state.phase = PHASE_PREFILL;
		new_state.prefill_start_ns = now;
		new_state.last_activity_ns = now;
		new_state.prefill_kernel_count = 1;
		new_state.first_request_ns = now;
		bpf_map_update_elem(&inference_states, &tgid, &new_state, BPF_ANY);
		return 0;
	}

	if (state->in_graph_capture)
		return 0;

	u64 gap = now - state->last_activity_ns;

	switch (state->phase) {
	case PHASE_IDLE:
		state->phase = PHASE_PREFILL;
		state->prefill_start_ns = now;
		state->last_activity_ns = now;
		state->prefill_kernel_count = 1;
		state->decode_start_ns = 0;
		state->last_token_ns = 0;
		state->decode_token_count = 0;
		if (state->first_request_ns == 0)
			state->first_request_ns = now;
		break;

	case PHASE_PREFILL:
		if (gap > gap_threshold_ns &&
		    state->prefill_kernel_count >= min_prefill_kernels) {
			/* PREFILL -> DECODE: emit TTFT event */
			struct ttft_event *event;
			event = gadget_reserve_buf(&ttft_events, sizeof(*event));
			if (event) {
				__builtin_memset(event, 0, sizeof(*event));
				gadget_process_populate(&event->proc);
				event->ttft_ns = state->last_activity_ns - state->prefill_start_ns;
				event->prefill_kernels = state->prefill_kernel_count;
				event->prefill_start = state->prefill_start_ns;
				event->prefill_end = state->last_activity_ns;
				gadget_submit_buf(ctx, &ttft_events, event, sizeof(*event));
			}

			state->phase = PHASE_DECODE;
			state->decode_start_ns = now;
			state->last_activity_ns = now;
			state->last_token_ns = 0;
			state->decode_token_count = 0;
		} else {
			state->last_activity_ns = now;
			state->prefill_kernel_count++;
		}
		break;

	case PHASE_DECODE:
		if (gap > cooldown_ns) {
			maybe_complete_inference(ctx, state, tgid, now);
			state->phase = PHASE_PREFILL;
			state->prefill_start_ns = now;
			state->last_activity_ns = now;
			state->prefill_kernel_count = 1;
			state->decode_start_ns = 0;
			state->last_token_ns = 0;
			state->decode_token_count = 0;
		} else {
			state->last_activity_ns = now;
		}
		break;
	}

	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(void *ctx)
{
	u32 tid;
	u32 tgid;
	u64 pid_tgid;

	pid_tgid = bpf_get_current_pid_tgid();
	tid = (u32)pid_tgid;
	tgid = (u32)(pid_tgid >> 32);

	bpf_map_delete_elem(&sizes, &tid);
	if (tid == tgid)
		bpf_map_delete_elem(&inference_states, &tgid);

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
/*
 * Handle activity during decode phase — cuGraphLaunch keeps
 * the state machine in DECODE and updates last_activity_ns.
 */
static __always_inline int handle_decode_activity(void *ctx)
{
	u64 pid_tgid;
	u32 tgid;
	u64 now;
	struct inference_state *state;

	if (gadget_should_discard_data_current())
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	tgid = (u32)(pid_tgid >> 32);
	now = bpf_ktime_get_ns();

	state = bpf_map_lookup_elem(&inference_states, &tgid);
	if (!state)
		return 0;

	if (state->phase == PHASE_DECODE) {
		u64 gap = now - state->last_activity_ns;
		if (gap > cooldown_ns) {
			maybe_complete_inference(ctx, state, tgid, now);
			return 0;
		}
		state->last_activity_ns = now;
	} else if (state->phase == PHASE_PREFILL) {
		state->last_activity_ns = now;
	}

	return 0;
}

/*
 * Handle DtoH async copy — token boundary signal.
 * Each cuMemcpyDtoHAsync during decode approximates one output token
 * (logits transfer from device to host).
 */
static __always_inline int handle_dth_async(void *ctx)
{
	u64 pid_tgid;
	u32 tgid;
	u64 now;
	struct inference_state *state;

	if (gadget_should_discard_data_current())
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	tgid = (u32)(pid_tgid >> 32);
	now = bpf_ktime_get_ns();

	state = bpf_map_lookup_elem(&inference_states, &tgid);
	if (!state)
		return 0;

	if (state->phase != PHASE_DECODE)
		return 0;

	u64 gap = now - state->last_activity_ns;
	if (gap > cooldown_ns) {
		maybe_complete_inference(ctx, state, tgid, now);
		return 0;
	}

	state->last_activity_ns = now;
	state->decode_token_count++;

	/* Emit ITL event if we have a previous token timestamp */
	if (state->last_token_ns > 0) {
		__u64 itl = now - state->last_token_ns;
		struct itl_event *event;
		event = gadget_reserve_buf(&itl_events, sizeof(*event));
		if (event) {
			__builtin_memset(event, 0, sizeof(*event));
			gadget_process_populate(&event->proc);
			event->itl_ns = itl;
			event->token_index = state->decode_token_count - 1;
			gadget_submit_buf(ctx, &itl_events, event, sizeof(*event));
		}
	}

	state->last_token_ns = now;
	return 0;
}

/* ── Inference metric uprobes ─────────────────────────────────── */

SEC("uprobe/libcuda:cuLaunchKernel")
int BPF_UPROBE(trace_uprobe_cuLaunchKernel)
{
	return handle_kernel_launch(ctx);
}

SEC("uprobe/libcuda:cuLaunchKernelEx")
int BPF_UPROBE(trace_uprobe_cuLaunchKernelEx)
{
	return handle_kernel_launch(ctx);
}

SEC("uprobe/libcuda:cuGraphLaunch")
int BPF_UPROBE(trace_uprobe_cuGraphLaunch)
{
	return handle_decode_activity(ctx);
}

SEC("uprobe/libcuda:cuGraphLaunch_ptsz")
int BPF_UPROBE(trace_uprobe_cuGraphLaunch_ptsz)
{
	return handle_decode_activity(ctx);
}

SEC("uprobe/libcuda:cuStreamBeginCapture_v2")
int BPF_UPROBE(trace_uprobe_cuStreamBeginCapture_v2)
{
	u64 pid_tgid;
	u32 tgid;
	struct inference_state *state;

	if (gadget_should_discard_data_current())
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	tgid = (u32)(pid_tgid >> 32);

	state = bpf_map_lookup_elem(&inference_states, &tgid);
	if (state)
		state->in_graph_capture = 1;

	return 0;
}

SEC("uprobe/libcuda:cuStreamEndCapture")
int BPF_UPROBE(trace_uprobe_cuStreamEndCapture)
{
	u64 pid_tgid;
	u32 tgid;
	struct inference_state *state;

	if (gadget_should_discard_data_current())
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	tgid = (u32)(pid_tgid >> 32);

	state = bpf_map_lookup_elem(&inference_states, &tgid);
	if (state)
		state->in_graph_capture = 0;

	return 0;
}

SEC("uprobe/libcuda:cuMemcpyDtoHAsync_v2")
int BPF_UPROBE(trace_uprobe_cuMemcpyDtoHAsync_v2)
{
	return handle_dth_async(ctx);
}

/* ── Memory allocation uprobes ────────────────────────────────── */

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
