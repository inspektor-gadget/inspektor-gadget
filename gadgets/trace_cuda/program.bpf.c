// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 Alejandro Salamanca */

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/user_stack_map.h>
#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns.h>
#include <gadget/types.h>
#include <gadget/bits.bpf.h>
#include <gadget/core_fixes.bpf.h>

//Type definition

#define MAX_ENTRIES 10240
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif
#define GPU_HIST_MAX_SLOTS 48
#define MAX_GPUKERN_ARGS 16
#define DIR_HTOD 0
#define DIR_DTOH 1

typedef __u64 CUdeviceptr;
typedef __u64 CUstream;

struct kernel_key {
	__u32 pid;
	__u32 correlation_id;
};

struct cupti_event {
	gadget_timestamp timestamp;
	gadget_mntns_id mntns_id;
	gadget_pid pid;
	gadget_comm comm[TASK_COMM_LEN];
	__u32 grid_x;
	__u32 grid_y;
	__u32 grid_z;

	__u32 block_x;
	__u32 block_y;
	__u32 block_z;

	__u32 correlation_id;

	__u64 start;
	__u64 end;

	struct gadget_user_stack ustack;
	__u32 stream;

	int ret_val;
};

struct memalloc_event {
	gadget_timestamp timestamp;
	gadget_mntns_id mntns_id;
	gadget_pid pid;
	gadget_comm comm[TASK_COMM_LEN];
	size_t byte_size;
	int ret_val;
};

struct memcpy_event {
	gadget_timestamp timestamp;
	gadget_mntns_id mntns_id;
	gadget_pid pid;
	gadget_comm comm[TASK_COMM_LEN];
	size_t byte_size;
	__u8 kind;
	int ret_val;
};

//Map definition

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct kernel_key);
	__type(value, struct cupti_event);
} kernel_event_cupti SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct memalloc_event);
} memalloc_event SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct memcpy_event);
} memcpy_event SEC(".maps");

// gadget macros
GADGET_PARAM(collect_ustack);

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER_MAP(memalloc_events, 1024 * 256);
GADGET_TRACER_MAP(memcpy_events, 1024 * 256);

GADGET_TRACER(cuda_mytracer, events, cupti_event);
GADGET_TRACER(memalloc_tracer, memalloc_events, memalloc_event);
GADGET_TRACER(memcpy_tracer, memcpy_events, memcpy_event);

//functions impl

static __always_inline int
handle_cuMemAlloc_impl(void **devptr, size_t bytesize, struct pt_regs *ctx)
{
	struct memalloc_event event = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	event.timestamp = bpf_ktime_get_boot_ns();
	event.mntns_id = gadget_get_current_mntns_id();
	event.pid = pid_tgid >> 32;

	event.byte_size = bytesize;

	bpf_map_update_elem(&memalloc_event, &pid_tgid, &event, BPF_ANY);

	return 0;
}

static __always_inline int handle_cuMemAlloc_exit_impl(int ret,
						       struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	struct memalloc_event *prev =
		bpf_map_lookup_elem(&memalloc_event, &pid_tgid);
	if (!prev)
		return 0;

	struct memalloc_event *event;
	event = gadget_reserve_buf(&memalloc_events, sizeof(*event));
	if (!event)
		goto clean;

	event->mntns_id = prev->mntns_id;
	event->timestamp = prev->timestamp;
	event->byte_size = prev->byte_size;
	event->pid = prev->pid;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	event->ret_val = ret;

	gadget_submit_buf(ctx, &memalloc_events, event, sizeof(*event));

clean:
	bpf_map_delete_elem(&memalloc_event, &pid_tgid);
	return 0;
}

static __always_inline int handle_cuMemcpy_htod_impl(CUdeviceptr dst,
						     const void *src,
						     size_t bytesize,
						     struct pt_regs *ctx)
{
	struct memcpy_event event = {};

	// process info
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	event.timestamp = bpf_ktime_get_boot_ns();
	event.mntns_id = gadget_get_current_mntns_id();
	event.pid = pid_tgid >> 32;

	event.byte_size = bytesize;
	event.kind = DIR_HTOD;

	bpf_map_update_elem(&memcpy_event, &pid_tgid, &event, BPF_ANY);
	return 0;
}

static __always_inline int handle_cuMemcpy_htod_exit_impl(int ret,
							  struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct memcpy_event *prev =
		bpf_map_lookup_elem(&memcpy_event, &pid_tgid);

	if (!prev)
		return 0;

	struct memcpy_event *event;
	event = gadget_reserve_buf(&memcpy_events, sizeof(*event));

	if (!event)
		goto clean;

	event->byte_size = prev->byte_size;
	event->pid = prev->pid;
	event->timestamp = prev->timestamp;
	event->mntns_id = prev->mntns_id;
	event->kind = prev->kind;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	event->ret_val = ret;

	gadget_submit_buf(ctx, &memcpy_events, event, sizeof(*event));

clean:
	bpf_map_delete_elem(&memcpy_event, &pid_tgid);
	return 0;
}

static __always_inline int handle_cuMemcpy_dtoh_impl(void *dst, CUdeviceptr src,
						     size_t bytesize,
						     struct pt_regs *ctx)
{
	struct memcpy_event event = {};

	// process info
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	event.timestamp = bpf_ktime_get_boot_ns();
	event.mntns_id = gadget_get_current_mntns_id();
	event.pid = pid_tgid >> 32;

	event.byte_size = bytesize;
	event.kind = DIR_DTOH;

	bpf_map_update_elem(&memcpy_event, &pid_tgid, &event, BPF_ANY);
	return 0;
}

static __always_inline int handle_cuMemcpy_dtoh_exit_impl(int ret,
							  struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct memcpy_event *prev =
		bpf_map_lookup_elem(&memcpy_event, &pid_tgid);
	if (!prev)
		return 0;

	struct memcpy_event *event;

	event = gadget_reserve_buf(&memcpy_events, sizeof(*event));
	if (!event)
		goto clean;

	event->timestamp = prev->timestamp;
	event->pid = prev->pid;
	event->mntns_id = prev->mntns_id;
	event->kind = prev->kind;
	event->byte_size = prev->byte_size;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	event->ret_val = ret;

	gadget_submit_buf(ctx, &memcpy_events, event, sizeof(*event));

clean:
	bpf_map_delete_elem(&memcpy_event, &pid_tgid);
	return 0;
}

static __always_inline int
handle_ig_callback_impl(struct pt_regs *ctx, __u32 correlation_id, __u64 result)
{
	if (result != 0)
		return 0;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct cupti_event event = {};
	event.timestamp = bpf_ktime_get_boot_ns();
	event.mntns_id = gadget_get_current_mntns_id();
	event.pid = pid_tgid >> 32;

	event.correlation_id = correlation_id;
	event.ret_val = (int)result;

	if (collect_ustack)
		gadget_get_user_stack(ctx, &event.ustack);

	struct kernel_key key = {
		.correlation_id = correlation_id,
		.pid = pid_tgid >> 32,
	};
	bpf_map_update_elem(&kernel_event_cupti, &key, &event, BPF_ANY);
	return 0;
}

static __always_inline int
handle_ig_activity_impl(struct pt_regs *ctx, __u32 correlation_id,
			__u32 device_id, __u32 stream_id, __u32 grid_x,
			__u32 grid_y, __u32 grid_z, __u32 block_x,
			__u32 block_y, __u32 block_z, __u64 start, __u64 end)
{
	struct cupti_event *prev;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct kernel_key key = {
		.correlation_id = correlation_id,
		.pid = pid_tgid >> 32,
	};

	prev = bpf_map_lookup_elem(&kernel_event_cupti, &key);
	if (!prev)
		return 0;

	struct cupti_event *event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		goto clean;

	event->timestamp = prev->timestamp;
	event->mntns_id = prev->mntns_id;
	event->pid = prev->pid;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	event->correlation_id = correlation_id;
	event->ret_val = prev->ret_val;

	event->block_x = block_x;
	event->block_y = block_y;
	event->block_z = block_z;

	event->grid_x = grid_x;
	event->grid_y = grid_y;
	event->grid_z = grid_z;

	event->stream = stream_id;

	event->start = start;
	event->end = end;

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

clean:
	bpf_map_delete_elem(&kernel_event_cupti, &key);
	return 0;
}
// uprobes

// USDT cupti

//  Arguments amd x86: 4@%eax 8@%rdx 8@%rcx 4@%esi 4@%edi 8@-72(%rbp) -4@%r8d 8@-64(%rbp) -4@%r9d
//  Arguments arm archh: 4@x1 8@x2 8@x3 4@x4 4@x5 8@[sp, 112] -4@x6 8@[sp, 120] -4@x0
SEC("usdt/libtrace_cuda_cupti:myprov:ig_activity")
int handle_ig_activity(struct pt_regs *ctx)
{
	__u32 correlation_id = 0, device_id = 0, stream_id = 0;
	__u64 start = 0, end = 0;

	__u32 grid_z = 0, block_z = 0;
	__u32 grid_x = 0, grid_y = 0;
	__u32 block_x = 0, block_y = 0;

#ifdef __TARGET_ARCH_x86
	__u64 grid_xy = 0, block_xy = 0;

	correlation_id = (__u32)ctx->ax;
	start = ctx->dx;
	end = ctx->cx;
	device_id = ctx->si;
	stream_id = (__u32)ctx->di;
	grid_z = (__u32)ctx->r8;
	block_z = (__u32)ctx->r9;

	__u64 rbp = ctx->bp;
	if (!rbp)
		return 0;

	if (bpf_probe_read_user(&grid_xy, sizeof(grid_xy), (void *)(rbp - 72)))
		return 0;

	if (bpf_probe_read_user(&block_xy, sizeof(block_xy),
				(void *)(rbp - 64)))
		return 0;

	grid_x = grid_xy >> 32;
	grid_y = grid_xy & 0xffffffff;

	block_x = block_xy >> 32;
	block_y = block_xy & 0xffffffff;

#endif

#ifdef __TARGET_ARCH_arm64
	__u64 grid_xy = 0, block_xy = 0;

	void *sp = (void *)ctx->sp;
	if (!sp)
		return 0;

	correlation_id = (__u32)ctx->regs[1];
	start = ctx->regs[2];
	end = ctx->regs[3];
	device_id = (__u32)ctx->regs[4];
	stream_id = (__u32)ctx->regs[5];

	grid_z = (__u32)ctx->regs[6];
	block_z = (__u32)ctx->regs[0];

	if (bpf_probe_read_user(&grid_xy, sizeof(grid_xy), sp + 112))
		return 0;

	if (bpf_probe_read_user(&block_xy, sizeof(block_xy), sp + 120))
		return 0;

	grid_x = grid_xy >> 32;
	grid_y = grid_xy & 0xffffffff;

	block_x = block_xy >> 32;
	block_y = block_xy & 0xffffffff;
#endif

	handle_ig_activity_impl(ctx, correlation_id, device_id, stream_id,
				grid_x, grid_y, grid_z, block_x, block_y,
				block_z, start, end);

	return 0;
}

// Arguments amd64 x86: 4@-60(%rbp) 4@-80(%rbp) 8@-40(%rbp) 8@-48(%rbp)
// Arguments arm AArch64: 4@[sp, 60] 4@[sp, 32] 8@[sp, 80] 8@[sp, 72]
SEC("usdt/libtrace_cuda_cupti:myprov:ig_callback")
int handle_ig_callback(struct pt_regs *ctx)
{
	__u32 correlation_id = 0;
	__u32 cbid = 0;
	__u64 result = 0;

#ifdef __TARGET_ARCH_x86
	__u64 rbp = ctx->bp;

	if (!rbp)
		return 0;

	/* arg1: 4@-60(%rbp) */
	if (bpf_probe_read_user(&correlation_id, sizeof(correlation_id),
				(void *)(rbp - 60)))
		return 0;

	/* arg2:  4@-80(%rbp) */
	if (bpf_probe_read_user(&cbid, sizeof(cbid), (void *)(rbp - 80)))
		return 0;

	/* arg4: 8@-48(%rbp) */
	if (bpf_probe_read_user(&result, sizeof(result), (void *)(rbp - 48)))
		return 0;

#endif

#ifdef __TARGET_ARCH_arm64

	void *sp = (void *)ctx->sp;
	if (!sp)
		return 0;

	/* arg1: 4@[sp,60] */
	if (bpf_probe_read_user(&correlation_id, sizeof(correlation_id),
				sp + 60))
		return 0;

	/* arg2: 4@[sp,32] */
	if (bpf_probe_read_user(&cbid, sizeof(cbid), sp + 32))
		return 0;

	/* arg4: 8@[sp,72] */
	if (bpf_probe_read_user(&result, sizeof(result), sp + 72))
		return 0;

#endif

	handle_ig_callback_impl(ctx, correlation_id, result);

	return 0;
}

//mem alloc
SEC("uprobe/libcuda:cuMemAlloc")
int BPF_KPROBE(handle_cuMemAlloc, void **devptr, size_t bytesize)
{
	return handle_cuMemAlloc_impl(devptr, bytesize, ctx);
}

SEC("uretprobe/libcuda:cuMemAlloc")
int BPF_KRETPROBE(handle_cuMemAlloc_exit, int ret)
{
	return handle_cuMemAlloc_exit_impl(ret, ctx);
}

SEC("uprobe/libcuda:cuMemAlloc_v2")
int BPF_KPROBE(handle_cuMemAlloc_v2, void **devptr, size_t bytesize)
{
	return handle_cuMemAlloc_impl(devptr, bytesize, ctx);
}

SEC("uretprobe/libcuda:cuMemAlloc_v2")
int BPF_KRETPROBE(handle_cuMemAlloc_exit_v2, int ret)
{
	return handle_cuMemAlloc_exit_impl(ret, ctx);
}

// memcpy
SEC("uprobe/libcuda:cuMemcpyHtoD")
int BPF_KPROBE(handle_cuMemcpy_htod, CUdeviceptr dst, const void *src,
	       size_t bytesize)
{
	return handle_cuMemcpy_htod_impl(dst, src, bytesize, ctx);
}

SEC("uretprobe/libcuda:cuMemcpyHtoD")
int BPF_KRETPROBE(handle_cuMemcpy_htod_exit, int ret)
{
	return handle_cuMemcpy_htod_exit_impl(ret, ctx);
}

SEC("uprobe/libcuda:cuMemcpyHtoD_v2")
int BPF_KPROBE(handle_cuMemcpy_htod_v2, CUdeviceptr dst, const void *src,
	       size_t bytesize)
{
	return handle_cuMemcpy_htod_impl(dst, src, bytesize, ctx);
}

SEC("uretprobe/libcuda:cuMemcpyHtoD_v2")
int BPF_KRETPROBE(handle_cuMemcpy_htod_exit_v2, int ret)
{
	return handle_cuMemcpy_htod_exit_impl(ret, ctx);
}

SEC("uprobe/libcuda:cuMemcpyHtoDAsync_v2")
int BPF_KPROBE(handle_cuMemcpy_htod_async_v2, CUdeviceptr dst, const void *src,
	       size_t bytesize, u64 stream)
{
	return handle_cuMemcpy_htod_impl(dst, src, bytesize, ctx);
}

SEC("uretprobe/libcuda:cuMemcpyHtoDAsync_v2")
int BPF_KRETPROBE(handle_cuMemcpy_htod_async_exit_v2, int ret)
{
	return handle_cuMemcpy_htod_exit_impl(ret, ctx);
}

SEC("uprobe/libcuda:cuMemcpyHtoDAsync")
int BPF_KPROBE(handle_cuMemcpy_htod_async, CUdeviceptr dst, const void *src,
	       size_t bytesize, u64 stream)
{
	return handle_cuMemcpy_htod_impl(dst, src, bytesize, ctx);
}

SEC("uretprobe/libcuda:cuMemcpyHtoDAsync")
int BPF_KRETPROBE(handle_cuMemcpy_htod_async_exit, int ret)
{
	return handle_cuMemcpy_htod_exit_impl(ret, ctx);
}

SEC("uprobe/libcuda:cuMemcpyDtoH")
int BPF_KPROBE(handle_cuMemcpy_dtoh, void *dst, CUdeviceptr src,
	       size_t bytesize)
{
	return handle_cuMemcpy_dtoh_impl(dst, src, bytesize, ctx);
}

SEC("uretprobe/libcuda:cuMemcpyDtoH")
int BPF_KRETPROBE(handle_cuMemcpy_dtoh_exit, int ret)
{
	return handle_cuMemcpy_dtoh_exit_impl(ret, ctx);
}

SEC("uprobe/libcuda:cuMemcpyDtoH_v2")
int BPF_KPROBE(handle_cuMemcpy_dtoh_v2, void *dst, CUdeviceptr src,
	       size_t bytesize)
{
	return handle_cuMemcpy_dtoh_impl(dst, src, bytesize, ctx);
}

SEC("uretprobe/libcuda:cuMemcpyDtoH_v2")
int BPF_KRETPROBE(handle_cuMemcpy_dtoh_exit_v2, int ret)
{
	return handle_cuMemcpy_dtoh_exit_impl(ret, ctx);
}

SEC("uprobe/libcuda:cuMemcpyDtoHAsync_v2")
int BPF_KPROBE(handle_cuMemcpy_dtoh_async_v2, void *dst, CUdeviceptr src,
	       size_t bytesize, u64 stream)
{
	return handle_cuMemcpy_dtoh_impl(dst, src, bytesize, ctx);
}

SEC("uretprobe/libcuda:cuMemcpyDtoHAsync_v2")
int BPF_KRETPROBE(handle_cuMemcpy_dtoh_async_exit_v2, int ret)
{
	return handle_cuMemcpy_dtoh_exit_impl(ret, ctx);
}

SEC("uprobe/libcuda:cuMemcpyDtoHAsync")
int BPF_KPROBE(handle_cuMemcpy_dtoh_async, void *dst, CUdeviceptr src,
	       size_t bytesize, u64 stream)
{
	return handle_cuMemcpy_dtoh_impl(dst, src, bytesize, ctx);
}

SEC("uretprobe/libcuda:cuMemcpyDtoHAsync")
int BPF_KRETPROBE(handle_cuMemcpy_dtoh_async_exit, int ret)
{
	return handle_cuMemcpy_dtoh_exit_impl(ret, ctx);
}

char LICENSE[] SEC("license") = "GPL";
