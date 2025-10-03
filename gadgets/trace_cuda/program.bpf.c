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
#include <gadget/user_stack_map.h>

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
    gadget_duration latency_ns_raw; // Set only if the operation is completed
    __u32 error;
    struct gadget_user_stack ustack;
};

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(cuda, events, event);

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct gadget_process);
	__type(value, __u64); // timestamp of the event
	__uint(max_entries, 1024);
} event_map SEC(".maps");

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
    struct gadget_process proc;
    __u64 timestamp;
	bpf_printk("cuMemAlloc ENTRY fired!");
    event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;
    event->timestamp_raw = bpf_ktime_get_boot_ns();
    event->latency_ns_raw = 0;
    event->error = 0;
    gadget_process_populate(&event->proc);
    event->event_type_raw = F_CU_MEM_ALLOC_E;
    gadget_get_user_stack(ctx, &event->ustack);

    // Copy to stack variables for map operations
    proc = event->proc;
    timestamp = event->timestamp_raw;
    bpf_map_update_elem(&event_map, &proc, &timestamp, BPF_NOEXIST);

    gadget_submit_buf(ctx, &events, event, sizeof(*event));
	return 0;
}

SEC("uretprobe/libcuda:cuMemAlloc_v2")
int BPF_UPROBE(ig_cu_mem_alloc_x)
{
    struct event *event;
    struct gadget_process proc;
	bpf_printk("cuMemAlloc EXIT fired!\n");
    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event)
		return 0;
    event->timestamp_raw = bpf_ktime_get_boot_ns();
    gadget_process_populate(&event->proc);
    event->event_type_raw = F_CU_MEM_ALLOC_X;
    gadget_get_user_stack(ctx, &event->ustack);
    event->error = PT_REGS_RC(ctx);
    // Copy proc to stack variable for map operations
    proc = event->proc;
    __u64 *event_ts = bpf_map_lookup_elem(&event_map, &proc);
    if (event_ts != NULL) {
        // event ts should always be less than the event->timestamp_raw, but
        // check anyway to be safe.
        if (*event_ts < event->timestamp_raw) {
            event->latency_ns_raw =
                event->timestamp_raw -
                *event_ts;
        }
        bpf_map_delete_elem(&event_map, &proc);
    }
    gadget_submit_buf(ctx, &events, event, sizeof(*event));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";