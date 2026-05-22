// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2026 The Inspektor Gadget authors */

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/types.h>

#include "go-utils.h"

#define METHOD_MAX_LEN 256
#define MAX_PAYLOAD_SIZE 4096

enum grpc_event_type {
	GRPC_EVENT_CALL = 0, // newClientStream: RPC initiated
	GRPC_EVENT_SEND = 1, // sendMsg: message sent on wire
};

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;
	char method[METHOD_MAX_LEN];
	enum grpc_event_type type_raw;
	__u32 payload_len; // full payload length from gRPC frame header
	__u8 compressed; // compression flag from gRPC frame header
	__u32 captured_len; // bytes actually captured in payload[]
	__u8 payload[MAX_PAYLOAD_SIZE];
};

#define BASE_EVENT_SIZE ((size_t)(&((struct event *)0)->payload))
#define EVENT_SIZE(X) (BASE_EVENT_SIZE + ((size_t)(X)))

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(grpc, events, event);

// Correlation map: goroutine pointer → method string.
// Used to associate newClientStream (method) with sendMsg (payload).
// Limitation: only reliable for sequential unary RPCs per goroutine.
struct method_info {
	char method[METHOD_MAX_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);
	__type(value, struct method_info);
} goroutine_method SEC(".maps");

// google.golang.org/grpc.newClientStream is the convergence point for both
// unary (Invoke) and streaming (NewStream) RPCs.
//
// Signature:
//   func newClientStream(ctx context.Context, desc *StreamDesc, cc *ClientConn, method string, opts ...CallOption)
//
// Go register ABI parameter assignment:
//   ctx (interface)     → GO_PARAM1 (type), GO_PARAM2 (value)
//   desc (*StreamDesc)  → GO_PARAM3
//   cc (*ClientConn)    → GO_PARAM4
//   method string       → GO_PARAM5 (ptr), GO_PARAM6 (len)
SEC("uprobe//tmp/ig-tests/trace-grpc-workload/client:google.golang.org/grpc.newClientStream")
int uprobe_new_client_stream(struct pt_regs *ctx)
{
	__u64 method_ptr = (__u64)GO_PARAM5(ctx);
	__u64 method_len = (__u64)GO_PARAM6(ctx);

	if (method_len == 0)
		return 0;

	// Clamp method_len to buffer size - 1 (leave room for NUL terminator)
	if (method_len >= METHOD_MAX_LEN)
		method_len = METHOD_MAX_LEN - 1;

	// Store method in goroutine correlation map for sendMsg lookup
	struct method_info info = {};
	bpf_probe_read_user(info.method, method_len & (METHOD_MAX_LEN - 1),
			    (void *)method_ptr);

	__u64 goroutine = (__u64)GOROUTINE_PTR(ctx);
	bpf_map_update_elem(&goroutine_method, &goroutine, &info, BPF_ANY);

	// Emit call event (no payload)
	struct event *event;
	event = gadget_reserve_buf(&events, BASE_EVENT_SIZE);
	if (!event)
		return 0;

	event->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&event->proc);
	event->type_raw = GRPC_EVENT_CALL;
	__builtin_memcpy(event->method, info.method, METHOD_MAX_LEN);
	event->payload_len = 0;
	event->compressed = 0;
	event->captured_len = 0;

	gadget_submit_buf(ctx, &events, event, BASE_EVENT_SIZE);
	return 0;
}

// google.golang.org/grpc.(*csAttempt).sendMsg captures the serialized
// protobuf payload as it is sent on the wire.
//
// Signature:
//   func (a *csAttempt) sendMsg(m any, hdr []byte, payld mem.BufferSlice, dataLength, payloadLength int) error
//
// Go register ABI parameter assignment:
//   a (*csAttempt)      → GO_PARAM1
//   m (any/interface)   → GO_PARAM2 (type), GO_PARAM3 (value)
//   hdr ([]byte)        → GO_PARAM4 (ptr), GO_PARAM5 (len), GO_PARAM6 (cap)
//   payld ([]Buffer)    → GO_PARAM7 (ptr), GO_PARAM8 (len), GO_PARAM9 (cap)
//   dataLength (int)    → stack spill
//   payloadLength (int) → stack spill
SEC("uprobe//tmp/ig-tests/trace-grpc-workload/client:google.golang.org/grpc.(*csAttempt).sendMsg")
int uprobe_cs_attempt_send_msg(struct pt_regs *ctx)
{
	__u64 goroutine = (__u64)GOROUTINE_PTR(ctx);

	// Read gRPC frame header (5 bytes): [compression_flag(1), payload_length(4 BE)]
	__u64 hdr_ptr = (__u64)GO_PARAM4(ctx);
	__u64 hdr_len = (__u64)GO_PARAM5(ctx);
	__u8 hdr[5] = {};

	__u8 compressed = 0;
	__u32 payload_len = 0;

	if (hdr_len >= 5 && hdr_ptr != 0) {
		if (bpf_probe_read_user(hdr, sizeof(hdr), (void *)hdr_ptr) ==
		    0) {
			compressed = hdr[0];
			payload_len = ((__u32)hdr[1] << 24) |
				      ((__u32)hdr[2] << 16) |
				      ((__u32)hdr[3] << 8) | (__u32)hdr[4];
		}
	}

	// Try to read protobuf payload from BufferSlice.
	// mem.BufferSlice = []Buffer (slice of interfaces).
	// Each interface element is (itab_ptr, value_ptr) = 16 bytes.
	// For the common sliceBuffer case (small messages):
	//   value_ptr → (data_ptr, data_len, data_cap) — it IS a []byte
	// For the pooled buffer case:
	//   value_ptr → (refs[8], data_ptr, data_len, data_cap, ...)
	// We try the sliceBuffer layout first and validate against payload_len.
	__u64 payld_ptr = (__u64)GO_PARAM7(ctx);
	__u64 payld_slice_len = (__u64)GO_PARAM8(ctx);

	__u32 captured_len = 0;
	__u32 copy_len = payload_len;
	if (copy_len > MAX_PAYLOAD_SIZE)
		copy_len = MAX_PAYLOAD_SIZE;

	struct event *event;
	// Reserve max size (verifier needs constant); submit with actual size
	event = gadget_reserve_buf(&events, sizeof(struct event));
	if (!event)
		return 0;

	event->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&event->proc);
	event->type_raw = GRPC_EVENT_SEND;

	// Look up method from goroutine correlation map
	struct method_info *info =
		bpf_map_lookup_elem(&goroutine_method, &goroutine);
	if (info) {
		__builtin_memcpy(event->method, info->method, METHOD_MAX_LEN);
	} else {
		__builtin_memset(event->method, 0, METHOD_MAX_LEN);
	}

	event->payload_len = payload_len;
	event->compressed = compressed;

	if (payld_slice_len > 0 && payld_ptr != 0 && copy_len > 0) {
		// Read first interface element: (itab_ptr[8], value_ptr[8])
		__u64 value_ptr = 0;
		bpf_probe_read_user(&value_ptr, sizeof(value_ptr),
				    (void *)(payld_ptr + 8));

		if (value_ptr != 0) {
			// Try sliceBuffer layout: value_ptr IS a []byte header
			__u64 data_ptr = 0;
			__u64 data_len = 0;
			bpf_probe_read_user(&data_ptr, sizeof(data_ptr),
					    (void *)value_ptr);
			bpf_probe_read_user(&data_len, sizeof(data_len),
					    (void *)(value_ptr + 8));

			// Validate: data_len should match payload_len
			if (data_ptr != 0 && data_len == payload_len) {
				bpf_probe_read_user(event->payload, copy_len,
						    (void *)data_ptr);
				captured_len = copy_len;
			}
		}
	}

	event->captured_len = captured_len;
	gadget_submit_buf(ctx, &events, event, EVENT_SIZE(captured_len));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
