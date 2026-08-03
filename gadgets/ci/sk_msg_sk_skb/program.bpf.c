// SPDX-License-Identifier: GPL-2.0
/* Copyright 2026 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/types.h>

#define GADGET_HTTP_AF_INET 2
#define GADGET_HTTP_PREFIX_LEN 24

enum gadget_http_program {
	GADGET_HTTP_SOCKHASH_ERROR,
	GADGET_HTTP_SK_MSG,
	GADGET_HTTP_SK_SKB,
};

struct gadget_http_sock_key {
	__u32 src_ip;
	__u32 dst_ip;
	__u32 src_port;
	__u32 dst_port;
};

struct gadget_http_event {
	enum gadget_http_program program_raw;
	__u32 len;
	char prefix[GADGET_HTTP_PREFIX_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	// This is a small test gadget, so tracking 1024 established endpoints is
	// enough while keeping the preallocated map footprint bounded.
	__uint(max_entries, 1024);
	__type(key, struct gadget_http_sock_key);
	__type(value, __u32);
} gadget_http_sockets SEC(".maps");

GADGET_TRACER_MAP(gadget_http_events, 256 * 1024);
GADGET_TRACER(http, gadget_http_events, gadget_http_event);

static __always_inline bool
gadget_http_is_http_prefix(const char prefix[GADGET_HTTP_PREFIX_LEN])
{
	return (prefix[0] == 'G' && prefix[1] == 'E' && prefix[2] == 'T' &&
		prefix[3] == ' ') ||
	       (prefix[0] == 'P' && prefix[1] == 'O' && prefix[2] == 'S' &&
		prefix[3] == 'T') ||
	       (prefix[0] == 'H' && prefix[1] == 'T' && prefix[2] == 'T' &&
		prefix[3] == 'P');
}

static __always_inline void
gadget_http_emit(void *ctx, enum gadget_http_program program, __u32 len,
		 const char prefix[GADGET_HTTP_PREFIX_LEN])
{
	struct gadget_http_event event = {
		.program_raw = program,
		.len = len,
	};

#pragma unroll
	for (int i = 0; i < GADGET_HTTP_PREFIX_LEN; i++)
		event.prefix[i] = prefix[i];

	gadget_output_buf(ctx, &gadget_http_events, &event, sizeof(event));
}

SEC("sockops")
int gadget_http_sockops(struct bpf_sock_ops *ops)
{
	if (ops->family != GADGET_HTTP_AF_INET)
		return 0;

	if (ops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB &&
	    ops->op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB)
		return 0;

	struct gadget_http_sock_key key = {
		.src_ip = ops->local_ip4,
		.dst_ip = ops->remote_ip4,
		.src_port = ops->local_port,
		// remote_port occupies the high 16 bits and is in network byte order.
		.dst_port = bpf_ntohl(ops->remote_port),
	};

	long ret =
		bpf_sock_hash_update(ops, &gadget_http_sockets, &key, BPF_ANY);
	if (ret) {
		char prefix[GADGET_HTTP_PREFIX_LEN] = {};

		gadget_http_emit(ops, GADGET_HTTP_SOCKHASH_ERROR, -ret, prefix);
	}

	return 0;
}

SEC("sk_msg")
int gadget_http_sk_msg(struct sk_msg_md *msg)
{
	char *data = (void *)(long)msg->data;
	char *data_end = (void *)(long)msg->data_end;
	char prefix[GADGET_HTTP_PREFIX_LEN] = {};

	if (data + sizeof(prefix) > data_end)
		return SK_PASS;

#pragma unroll
	for (int i = 0; i < GADGET_HTTP_PREFIX_LEN; i++)
		prefix[i] = data[i];

	if (gadget_http_is_http_prefix(prefix))
		gadget_http_emit(msg, GADGET_HTTP_SK_MSG, msg->size, prefix);

	return SK_PASS;
}
GADGET_SK_TARGET_MAP(gadget_http_sk_msg, gadget_http_sockets);

SEC("sk_skb/stream_parser")
int gadget_http_stream_parser(struct __sk_buff *skb)
{
	return skb->len;
}
GADGET_SK_TARGET_MAP(gadget_http_stream_parser, gadget_http_sockets);

SEC("sk_skb/stream_verdict")
int gadget_http_stream_verdict(struct __sk_buff *skb)
{
	char prefix[GADGET_HTTP_PREFIX_LEN] = {};

	if (skb->len < sizeof(prefix))
		return SK_PASS;
	if (bpf_skb_load_bytes(skb, 0, prefix, sizeof(prefix)))
		return SK_PASS;

	if (gadget_http_is_http_prefix(prefix))
		gadget_http_emit(skb, GADGET_HTTP_SK_SKB, skb->len, prefix);

	return SK_PASS;
}
GADGET_SK_TARGET_MAP(gadget_http_stream_verdict, gadget_http_sockets);

char LICENSE[] SEC("license") = "GPL";
