/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2025 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>

enum cuda_event {
	F_MALLOC_E,
    F_MALLOC_X,
    F_CU_MEM_ALLOC_E,
    F_CU_MEM_ALLOC_X,
};

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;
	enum cuda_event event_type_raw;
};

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(cuda, events, event);

// -------------------------------------------
// cudaMalloc() from libcudart.so
// -------------------------------------------

// SEC("uprobe/libcudart.so:cudaMalloc")
// int BPF_UPROBE(ig_cuda_malloc_e)
// {
//     struct event *event;
// 	bpf_printk("cudaMalloc() called");
//     event = gadget_reserve_buf(&events, sizeof(*event));
// 	if (!event)
// 		return 0;
//     event->timestamp_raw = bpf_ktime_get_boot_ns();
//     gadget_process_populate(&event->proc);
//     event->event_type_raw = F_MALLOC_E;
//     gadget_submit_buf(ctx, &events, event, sizeof(*event));
// 	return 0;
// }

// SEC("uretprobe/libcudart.so:cudaMalloc")
// int BPF_UPROBE(ig_cuda_malloc_x)
// {
//     struct event *event;
// 	bpf_printk("cudaMalloc() completed");
//     event = gadget_reserve_buf(&events, sizeof(*event));
//     if (!event)
//         return 0;
//     event->timestamp_raw = bpf_ktime_get_boot_ns();
//     gadget_process_populate(&event->proc);
//     event->event_type_raw = F_MALLOC_X;
//     gadget_submit_buf(ctx, &events, event, sizeof(*event));
// 	return 0;
// }

// -------------------------------------------
// cuMemAlloc() from libcuda.so (driver API)
// -------------------------------------------

SEC("uprobe/libcuda:cuMemAlloc_v2")
int BPF_UPROBE(ig_cu_mem_alloc_e)
{
    struct event *event;
	bpf_printk("cuMemAlloc ENTRY fired!\n");
    event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;
    event->timestamp_raw = bpf_ktime_get_boot_ns();
    gadget_process_populate(&event->proc);
    event->event_type_raw = F_CU_MEM_ALLOC_E;
    gadget_submit_buf(ctx, &events, event, sizeof(*event));
	return 0;
}

SEC("uretprobe/libcuda:cuMemAlloc_v2")
int BPF_UPROBE(ig_cu_mem_alloc_x)
{
    struct event *event;
	bpf_printk("cuMemAlloc EXIT fired!\n");
    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event)
		return 0;
    event->timestamp_raw = bpf_ktime_get_boot_ns();
    gadget_process_populate(&event->proc);
    event->event_type_raw = F_CU_MEM_ALLOC_X;
    gadget_submit_buf(ctx, &events, event, sizeof(*event));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";