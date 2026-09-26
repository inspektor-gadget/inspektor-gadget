// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */

#ifndef __BUFFER_BPF_H
#define __BUFFER_BPF_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#ifndef GADGET_MAX_EVENT_SIZE
#define GADGET_MAX_EVENT_SIZE 10240
#endif

// GADGET_TRACER_MAP defines the ring buffer map a tracer writes events into,
// together with a companion per-CPU lost-samples map. The ring buffer map is
// tagged with ig:tracer_map so IG can find it (and downgrade it to a perf event
// array when BPF ring buffers are unavailable). The legacy gadget_map_tracer_
// name-encoding is still read for pre-built images (see
// pkg/operators/ebpf/types.go).
#define GADGET_TRACER_MAP(name, size)                                       \
	struct {                                                            \
		__uint(type, BPF_MAP_TYPE_RINGBUF);                         \
		__uint(max_entries, size);                                  \
	} name __attribute__((btf_decl_tag("ig:tracer_map"))) SEC(".maps"); \
                                                                            \
	struct {                                                            \
		__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);                    \
		__uint(max_entries, 1);                                     \
		__uint(key_size, sizeof(__u32));                            \
		__uint(value_size, sizeof(__u64));                          \
	} name##_lost_samples SEC(".maps");

#ifndef GADGET_NO_BUF_RESERVE
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, GADGET_MAX_EVENT_SIZE);
} gadget_heap SEC(".maps");

// _lost_samples has to be suffixed because user will give &map as argument.
#define gadget_reserve_buf(map, size) \
	__gadget_reserve_buf(map, map##_lost_samples, size)

static __always_inline void *__gadget_reserve_buf(void *map, void *lost_samples,
						  __u64 size)
{
	const int zero = 0;

	if (bpf_core_enum_value_exists(enum bpf_func_id,
				       BPF_FUNC_ringbuf_reserve)) {
		void *mem = bpf_ringbuf_reserve(map, size, 0);
		if (mem == NULL) {
			__u64 *cnt = bpf_map_lookup_elem(lost_samples, &zero);
			if (cnt)
				*cnt += 1;
		}
		return mem;
	}

	return bpf_map_lookup_elem(&gadget_heap, &zero);
}

static __always_inline void gadget_discard_buf(void *buf)
{
	if (bpf_core_enum_value_exists(enum bpf_func_id,
				       BPF_FUNC_ringbuf_discard))
		bpf_ringbuf_discard(buf, 0);
}

static __always_inline long gadget_submit_buf(void *ctx, void *map, void *buf,
					      __u64 size)
{
	if (bpf_core_enum_value_exists(enum bpf_func_id,
				       BPF_FUNC_ringbuf_submit)) {
		bpf_ringbuf_submit(buf, 0);
		return 0;
	}

	return bpf_perf_event_output(ctx, map, BPF_F_CURRENT_CPU, buf, size);
}
#endif /* GADGET_NO_BUF_RESERVE */

// _lost_samples has to be suffixed because user will give &map as argument.
#define gadget_output_buf(ctx, map, buf, size) \
	__gadget_output_buf(ctx, map, map##_lost_samples, buf, size)

static __always_inline long __gadget_output_buf(void *ctx, void *map,
						void *lost_samples, void *buf,
						__u64 size)
{
	if (bpf_core_enum_value_exists(enum bpf_func_id,
				       BPF_FUNC_ringbuf_output)) {
		long ret = bpf_ringbuf_output(map, buf, size, 0);
		if (ret) {
			const int zero = 0;
			__u64 *cnt = bpf_map_lookup_elem(lost_samples, &zero);
			if (cnt)
				*cnt += 1;
		}
		return 0;
	}

	return bpf_perf_event_output(ctx, map, BPF_F_CURRENT_CPU, buf, size);
}

#endif /* __BUFFER_BPF_H */
