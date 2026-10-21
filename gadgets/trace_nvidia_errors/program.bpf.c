// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 The Inspektor Gadget authors

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/types.h>
#include <gadget/macros.h>
#include <gadget/user_stack_map.h>

#define MAX_ENTRIES 16384

/* Event source discriminator */
enum error_source {
	SOURCE_CUDA_API = 1,
	SOURCE_XID = 2,
};

/* CUDA_SUCCESS — the only return we do NOT record */
#define CUDA_SUCCESS 0

/*
 * API IDs — stable identifiers for each hooked libcuda function.
 * Kept as #define (not enum) so they match the WASM catalog's uint32 keys
 * directly without sign-extension ambiguity.
 */
#define API_cuMemAlloc_v2 1
#define API_cuMemAllocPitch_v2 2
#define API_cuMemAllocManaged 3
#define API_cuLaunchKernel 4
#define API_cuCtxCreate_v2 5
#define API_cuDeviceGet 6
#define API_cuDeviceGetCount 7
#define API_cuModuleLoad 8
#define API_cuModuleLoadData 9
#define API_cuModuleGetFunction 10
#define API_cuMemcpyHtoD_v2 11
#define API_cuMemcpyDtoH_v2 12
#define API_cuStreamCreate 13
#define API_cuStreamQuery 14
#define API_cuStreamSynchronize 15
#define API_cuEventCreate 16
#define API_cuEventRecord 17
#define API_cuEventQuery 18
#define API_cuEventSynchronize 19
#define API_cuMemFree_v2 20
#define API_cuCtxSynchronize 21
#define API_cuInit 22

/* XID→workload attribution flags (bitmask) */
#define XID_ATTRIB_PID_FROM_CONTEXT 0x1
#define XID_ATTRIB_CUDA_RING_MATCH 0x2
#define XID_ATTRIB_USER_STACK 0x4
#define XID_ATTRIB_GLOBAL_RING 0x8 /* fell back to cross-PID ring */
#define XID_ATTRIB_INTERRUPT_CTX 0x10 /* PID captured is a kernel IRQ thread */

/* Ring-match window for XID ↔ recent CUDA call correlation. */
#define CUDA_RING_MATCH_WINDOW_NS (100ULL * 1000ULL * 1000ULL)

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;

	__u32 source_raw; /* enum error_source */

	__s32 error_code_raw; /* CUresult; 0 for XID */
	__u32 api_id_raw; /* API_*; 0 for XID */

	__u32 xid_code;
	__u32 pci_domain;
	__u8 pci_bus;
	__u8 pci_slot;
	__u8 pci_func;
	__u8 _pad;

	__u64 arg1;
	__u64 arg2;
	__u64 arg3;
	__u64 arg4;
	__u64 arg5;
	__u64 arg6;

	/* XID→workload correlation (zero on CUDA-API events) */
	__u32 active_cuda_api; /* API_* id of matched recent call, 0 if none */
	__u32 xid_attrib_flags; /* XID_ATTRIB_* bitmask */
	__s64 active_cuda_delta_ns; /* xid_ts - last_cuda_ts (ns); 0 if no match */

	struct gadget_user_stack ustack_raw;
};

/* Per-TID stash so uretprobe can emit the args captured at entry. */
struct entry_args {
	__u32 api_id;
	__u32 _pad;
	__u64 arg1;
	__u64 arg2;
	__u64 arg3;
	__u64 arg4;
	__u64 arg5;
	__u64 arg6;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64); /* bpf_get_current_pid_tgid() */
	__type(value, struct entry_args);
} entries SEC(".maps");

/*
 * Per-TID "last CUDA call" record, stamped unconditionally on every
 * uretprobe. Used to attribute XID events to the most recent CUDA activity
 * from the same thread when the XID fires in process context.
 *
 * LRU_HASH so the map auto-evicts entries from exited threads.
 */
struct cuda_last_call {
	__u32 api_id;
	__u32 _pad;
	__u64 ts_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32); /* tgid */
	__type(value, struct cuda_last_call);
} cuda_last SEC(".maps");

/*
 * Single "most recent CUDA call across any PID" slot.  Used as the
 * strategy-C fallback when an XID fires in IRQ/DPC context — it attributes
 * to the PID that most recently touched the GPU, which is a reasonable
 * heuristic on single-GPU / single-tenant nodes and is marked with the
 * XID_ATTRIB_GLOBAL_RING flag so user-space can surface lower confidence.
 */
struct cuda_last_any {
	struct cuda_last_call call;
	struct gadget_process proc;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cuda_last_any);
} cuda_last_any SEC(".maps");

GADGET_TRACER_MAP(events, 1024 * 512);
GADGET_TRACER(nvidia_errors, events, event);

static __always_inline int save_entry(__u32 api_id, __u64 a1, __u64 a2,
				      __u64 a3, __u64 a4, __u64 a5, __u64 a6)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct entry_args args = {
		.api_id = api_id,
		._pad = 0,
		.arg1 = a1,
		.arg2 = a2,
		.arg3 = a3,
		.arg4 = a4,
		.arg5 = a5,
		.arg6 = a6,
	};
	bpf_map_update_elem(&entries, &pid_tgid, &args, BPF_ANY);
	return 0;
}

static __always_inline int handle_return(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct entry_args *args = bpf_map_lookup_elem(&entries, &pid_tgid);
	if (!args)
		return 0;

	__s32 ret = (__s32)PT_REGS_RC(ctx);

	/* Always stamp the per-TGID "last CUDA call" record — success or
	 * failure — so an XID arriving within 100 ms can attribute to the
	 * right workload even when the CUDA call itself succeeded, and even
	 * when the XID is reported from the CUDA driver's internal event
	 * handler thread rather than the one that submitted the API call.
	 */
	__u32 tgid_key = (__u32)(pid_tgid >> 32);
	struct cuda_last_call rec = {
		.api_id = args->api_id,
		.ts_ns = bpf_ktime_get_boot_ns(),
	};
	bpf_map_update_elem(&cuda_last, &tgid_key, &rec, BPF_ANY);

	/*
	 * Only update the global-ring slot for APIs that can plausibly submit
	 * GPU work or release resources (and thus trigger an XID).  Hot
	 * polling APIs (cuStreamQuery, cuEventQuery, cuEventRecord) are not
	 * instrumented at all to avoid overhead in ML inference workloads.
	 */
	switch (args->api_id) {
	case API_cuLaunchKernel:
	case API_cuMemcpyHtoD_v2:
	case API_cuMemcpyDtoH_v2:
	case API_cuCtxSynchronize:
	case API_cuStreamSynchronize:
	case API_cuMemFree_v2:
	case API_cuMemAlloc_v2:
	case API_cuMemAllocManaged:
	case API_cuMemAllocPitch_v2:
	case API_cuCtxCreate_v2:
	case API_cuModuleLoad:
	case API_cuModuleLoadData:
	case API_cuModuleGetFunction:
	case API_cuEventSynchronize: {
		__u32 zero = 0;
		struct cuda_last_any g = { .call = rec };
		gadget_process_populate(&g.proc);
		bpf_map_update_elem(&cuda_last_any, &zero, &g, BPF_ANY);
		break;
	}
	default:
		break;
	}

	if (ret == CUDA_SUCCESS) {
		bpf_map_delete_elem(&entries, &pid_tgid);
		return 0;
	}

	struct event *e = gadget_reserve_buf(&events, sizeof(*e));
	if (!e) {
		bpf_map_delete_elem(&entries, &pid_tgid);
		return 0;
	}

	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);

	e->source_raw = SOURCE_CUDA_API;
	e->error_code_raw = ret;
	e->api_id_raw = args->api_id;
	e->arg1 = args->arg1;
	e->arg2 = args->arg2;
	e->arg3 = args->arg3;
	e->arg4 = args->arg4;
	e->arg5 = args->arg5;
	e->arg6 = args->arg6;

	gadget_get_user_stack(ctx, &e->ustack_raw);
	gadget_submit_buf(ctx, &events, e, sizeof(*e));
	bpf_map_delete_elem(&entries, &pid_tgid);
	return 0;
}

/* ─── Process exit cleanup ────────────────────────────────────────────────
 * If a thread is killed (e.g. SIGKILL) between a uprobe entry and the
 * corresponding uretprobe, the entries map entry leaks. This tracepoint
 * fires for every exiting thread and removes any stale entry.
 */
SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(void *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&entries, &pid_tgid);
	return 0;
}

/* ─── XID kprobe ──────────────────────────────────────────────────────────
 * nv_report_error is exported by the NVIDIA kernel module (open-source build).
 * Signature: void nv_report_error(struct pci_dev *dev, NvU32 error_number,
 *                                 const char *format, va_list ap);
 *
 * Correlation with the offending workload:
 *   1. Process context: bpf_get_current_pid_tgid() — reliable when
 *      nv_report_error is invoked from a user ioctl (XID 13/31/43/45).
 *      For XIDs raised from IRQ/DPC (48/61/62/63/64/79) it is noise;
 *      the XID_ATTRIB_PID_FROM_CONTEXT flag lets user-space filter.
 *   2. Recent CUDA call: if the same TID ran a libcuda API within
 *      CUDA_RING_MATCH_WINDOW_NS, surface it on the XID event.
 *   3. User stack: gadget_get_user_stack() is a no-op when current is
 *      not a user thread, so unconditionally calling it is safe.
 */
SEC("kprobe/nv_report_error")
int BPF_KPROBE(trace_nv_report_error, struct pci_dev *dev, __u32 error_number)
{
	struct event *e = gadget_reserve_buf(&events, sizeof(*e));
	if (!e)
		return 0;

	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);

	e->source_raw = SOURCE_XID;
	e->xid_code = error_number;

	if (dev) {
		e->pci_bus = BPF_CORE_READ(dev, bus, number);
		__u32 devfn = BPF_CORE_READ(dev, devfn);
		e->pci_slot = devfn >> 3;
		e->pci_func = devfn & 0x7;
		e->pci_domain = 0;
	}

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = (__u32)(pid_tgid >> 32);
	__u32 flags = 0;

	if (pid != 0)
		flags |= XID_ATTRIB_PID_FROM_CONTEXT;

	struct cuda_last_call *last = bpf_map_lookup_elem(&cuda_last, &pid);
	if (last) {
		__s64 delta = (__s64)(e->timestamp_raw - last->ts_ns);
		if (delta >= 0 && delta <= (__s64)CUDA_RING_MATCH_WINDOW_NS) {
			e->active_cuda_api = last->api_id;
			e->active_cuda_delta_ns = delta;
			flags |= XID_ATTRIB_CUDA_RING_MATCH;
		}
	}
	/*
	 * Strategy-C fallback: if no per-PID hit (common for XID 31/48/79
	 * which are raised from IRQ/DPC context), use the global "most
	 * recent CUDA call across any PID" slot.  Widen the window to 2s.
	 */
	if (!(flags & XID_ATTRIB_CUDA_RING_MATCH)) {
		__u32 zero = 0;
		struct cuda_last_any *g =
			bpf_map_lookup_elem(&cuda_last_any, &zero);
		if (g && g->call.ts_ns) {
			__s64 delta = (__s64)(e->timestamp_raw - g->call.ts_ns);
			if (delta >= 0 &&
			    delta <= (__s64)(CUDA_RING_MATCH_WINDOW_NS * 20)) {
				e->active_cuda_api = g->call.api_id;
				e->active_cuda_delta_ns = delta;
				/* Replace interrupt-ctx proc snapshot with the
				 * offending workload's captured proc so the
				 * downstream container enricher can resolve it
				 * to the right K8s pod. */
				flags |= XID_ATTRIB_GLOBAL_RING;
				flags |= XID_ATTRIB_INTERRUPT_CTX;
				flags &= ~XID_ATTRIB_PID_FROM_CONTEXT;
				__builtin_memcpy(&e->proc, &g->proc,
						 sizeof(e->proc));
			}
		}
	}

	gadget_get_user_stack(ctx, &e->ustack_raw);
	flags |= XID_ATTRIB_USER_STACK;
	e->xid_attrib_flags = flags;

	gadget_submit_buf(ctx, &events, e, sizeof(*e));
	return 0;
}

/* ─── libcuda uprobes (22 entry/return pairs) ───────────────────────────── */

SEC("uprobe/libcuda:cuInit")
int BPF_UPROBE(probe_cuInit_entry, unsigned int flags)
{
	return save_entry(API_cuInit, flags, 0, 0, 0, 0, 0);
}
SEC("uretprobe/libcuda:cuInit")
int BPF_URETPROBE(probe_cuInit_return)
{
	return handle_return(ctx);
}

SEC("uprobe/libcuda:cuDeviceGet")
int BPF_UPROBE(probe_cuDeviceGet_entry, void *device, int ordinal)
{
	return save_entry(API_cuDeviceGet, (__u64)(unsigned long)device,
			  ordinal, 0, 0, 0, 0);
}
SEC("uretprobe/libcuda:cuDeviceGet")
int BPF_URETPROBE(probe_cuDeviceGet_return)
{
	return handle_return(ctx);
}

SEC("uprobe/libcuda:cuDeviceGetCount")
int BPF_UPROBE(probe_cuDeviceGetCount_entry, void *count)
{
	return save_entry(API_cuDeviceGetCount, (__u64)(unsigned long)count, 0,
			  0, 0, 0, 0);
}
SEC("uretprobe/libcuda:cuDeviceGetCount")
int BPF_URETPROBE(probe_cuDeviceGetCount_return)
{
	return handle_return(ctx);
}

SEC("uprobe/libcuda:cuCtxCreate_v2")
int BPF_UPROBE(probe_cuCtxCreate_entry, void *pctx, unsigned int flags, int dev)
{
	return save_entry(API_cuCtxCreate_v2, (__u64)(unsigned long)pctx, flags,
			  dev, 0, 0, 0);
}
SEC("uretprobe/libcuda:cuCtxCreate_v2")
int BPF_URETPROBE(probe_cuCtxCreate_return)
{
	return handle_return(ctx);
}

SEC("uprobe/libcuda:cuCtxSynchronize")
int BPF_UPROBE(probe_cuCtxSynchronize_entry)
{
	return save_entry(API_cuCtxSynchronize, 0, 0, 0, 0, 0, 0);
}
SEC("uretprobe/libcuda:cuCtxSynchronize")
int BPF_URETPROBE(probe_cuCtxSynchronize_return)
{
	return handle_return(ctx);
}

SEC("uprobe/libcuda:cuMemAlloc_v2")
int BPF_UPROBE(probe_cuMemAlloc_entry, void *dptr, __u64 bytesize)
{
	return save_entry(API_cuMemAlloc_v2, (__u64)(unsigned long)dptr,
			  bytesize, 0, 0, 0, 0);
}
SEC("uretprobe/libcuda:cuMemAlloc_v2")
int BPF_URETPROBE(probe_cuMemAlloc_return)
{
	return handle_return(ctx);
}

SEC("uprobe/libcuda:cuMemAllocPitch_v2")
int BPF_UPROBE(probe_cuMemAllocPitch_entry, void *dptr, void *pitch,
	       __u64 width, __u64 height, unsigned int element_size)
{
	return save_entry(API_cuMemAllocPitch_v2, (__u64)(unsigned long)dptr,
			  (__u64)(unsigned long)pitch, width, height,
			  element_size, 0);
}
SEC("uretprobe/libcuda:cuMemAllocPitch_v2")
int BPF_URETPROBE(probe_cuMemAllocPitch_return)
{
	return handle_return(ctx);
}

SEC("uprobe/libcuda:cuMemAllocManaged")
int BPF_UPROBE(probe_cuMemAllocManaged_entry, void *dptr, __u64 bytesize,
	       unsigned int flags)
{
	return save_entry(API_cuMemAllocManaged, (__u64)(unsigned long)dptr,
			  bytesize, flags, 0, 0, 0);
}
SEC("uretprobe/libcuda:cuMemAllocManaged")
int BPF_URETPROBE(probe_cuMemAllocManaged_return)
{
	return handle_return(ctx);
}

SEC("uprobe/libcuda:cuMemFree_v2")
int BPF_UPROBE(probe_cuMemFree_entry, __u64 dptr)
{
	return save_entry(API_cuMemFree_v2, dptr, 0, 0, 0, 0, 0);
}
SEC("uretprobe/libcuda:cuMemFree_v2")
int BPF_URETPROBE(probe_cuMemFree_return)
{
	return handle_return(ctx);
}

SEC("uprobe/libcuda:cuMemcpyHtoD_v2")
int BPF_UPROBE(probe_cuMemcpyHtoD_entry, __u64 dst, const void *src,
	       __u64 bytes)
{
	return save_entry(API_cuMemcpyHtoD_v2, dst, (__u64)(unsigned long)src,
			  bytes, 0, 0, 0);
}
SEC("uretprobe/libcuda:cuMemcpyHtoD_v2")
int BPF_URETPROBE(probe_cuMemcpyHtoD_return)
{
	return handle_return(ctx);
}

SEC("uprobe/libcuda:cuMemcpyDtoH_v2")
int BPF_UPROBE(probe_cuMemcpyDtoH_entry, void *dst, __u64 src, __u64 bytes)
{
	return save_entry(API_cuMemcpyDtoH_v2, (__u64)(unsigned long)dst, src,
			  bytes, 0, 0, 0);
}
SEC("uretprobe/libcuda:cuMemcpyDtoH_v2")
int BPF_URETPROBE(probe_cuMemcpyDtoH_return)
{
	return handle_return(ctx);
}

SEC("uprobe/libcuda:cuModuleLoad")
int BPF_UPROBE(probe_cuModuleLoad_entry, void *module, const char *fname)
{
	return save_entry(API_cuModuleLoad, (__u64)(unsigned long)module,
			  (__u64)(unsigned long)fname, 0, 0, 0, 0);
}
SEC("uretprobe/libcuda:cuModuleLoad")
int BPF_URETPROBE(probe_cuModuleLoad_return)
{
	return handle_return(ctx);
}

SEC("uprobe/libcuda:cuModuleLoadData")
int BPF_UPROBE(probe_cuModuleLoadData_entry, void *module, const void *image)
{
	return save_entry(API_cuModuleLoadData, (__u64)(unsigned long)module,
			  (__u64)(unsigned long)image, 0, 0, 0, 0);
}
SEC("uretprobe/libcuda:cuModuleLoadData")
int BPF_URETPROBE(probe_cuModuleLoadData_return)
{
	return handle_return(ctx);
}

SEC("uprobe/libcuda:cuModuleGetFunction")
int BPF_UPROBE(probe_cuModuleGetFunction_entry, void *hfunc, void *hmod,
	       const char *name)
{
	return save_entry(API_cuModuleGetFunction, (__u64)(unsigned long)hfunc,
			  (__u64)(unsigned long)hmod,
			  (__u64)(unsigned long)name, 0, 0, 0);
}
SEC("uretprobe/libcuda:cuModuleGetFunction")
int BPF_URETPROBE(probe_cuModuleGetFunction_return)
{
	return handle_return(ctx);
}

SEC("uprobe/libcuda:cuLaunchKernel")
int BPF_UPROBE(probe_cuLaunchKernel_entry, void *f, unsigned int gridX,
	       unsigned int gridY, unsigned int gridZ, unsigned int blockX,
	       unsigned int blockY)
{
	return save_entry(API_cuLaunchKernel, (__u64)(unsigned long)f, gridX,
			  gridY, gridZ, blockX, blockY);
}
SEC("uretprobe/libcuda:cuLaunchKernel")
int BPF_URETPROBE(probe_cuLaunchKernel_return)
{
	return handle_return(ctx);
}

SEC("uprobe/libcuda:cuStreamCreate")
int BPF_UPROBE(probe_cuStreamCreate_entry, void *phstream, unsigned int flags)
{
	return save_entry(API_cuStreamCreate, (__u64)(unsigned long)phstream,
			  flags, 0, 0, 0, 0);
}
SEC("uretprobe/libcuda:cuStreamCreate")
int BPF_URETPROBE(probe_cuStreamCreate_return)
{
	return handle_return(ctx);
}

SEC("uprobe/libcuda:cuStreamSynchronize")
int BPF_UPROBE(probe_cuStreamSynchronize_entry, void *hstream)
{
	return save_entry(API_cuStreamSynchronize,
			  (__u64)(unsigned long)hstream, 0, 0, 0, 0, 0);
}
SEC("uretprobe/libcuda:cuStreamSynchronize")
int BPF_URETPROBE(probe_cuStreamSynchronize_return)
{
	return handle_return(ctx);
}

SEC("uprobe/libcuda:cuEventCreate")
int BPF_UPROBE(probe_cuEventCreate_entry, void *phevent, unsigned int flags)
{
	return save_entry(API_cuEventCreate, (__u64)(unsigned long)phevent,
			  flags, 0, 0, 0, 0);
}
SEC("uretprobe/libcuda:cuEventCreate")
int BPF_URETPROBE(probe_cuEventCreate_return)
{
	return handle_return(ctx);
}

SEC("uprobe/libcuda:cuEventSynchronize")
int BPF_UPROBE(probe_cuEventSynchronize_entry, void *hevent)
{
	return save_entry(API_cuEventSynchronize, (__u64)(unsigned long)hevent,
			  0, 0, 0, 0, 0);
}
SEC("uretprobe/libcuda:cuEventSynchronize")
int BPF_URETPROBE(probe_cuEventSynchronize_return)
{
	return handle_return(ctx);
}

char LICENSE[] SEC("license") = "GPL";
