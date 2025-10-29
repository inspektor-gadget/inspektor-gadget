// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 The Inspektor Gadget authors */

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/buffer.h>
#include <gadget/filter.h>
#include <gadget/packetfilter.h>

#define GADGET_TYPE_NETWORKING
#include <gadget/sockets-map.h>

#define MAX_PKT_LEN 1500

#define PACKET_TYPE_EGRESS 0
#define PACKET_TYPE_INGRESS 1

struct packet_event_t {
	gadget_timestamp timestamp_raw;
	u8 packet_type;
	u32 ifindex;
	u32 payload_len;
	u32 packet_size;
	struct gadget_process proc;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} packets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct packet_event_t));
} tmp_packets SEC(".maps");

GADGET_TRACER(packets, packets, packet_event_t);

const volatile __u16 snaplen = MAX_PKT_LEN;
GADGET_PARAM(snaplen);

GADGET_PF();

static __always_inline int handle(struct __sk_buff *skb, __u8 packet_type)
{
	if (!gadget_pf_matches((void *)skb, (void *)(long)skb->data,
			       (void *)(long)skb->data_end))
		return 0;

	__u8 is_ingress = (packet_type == PACKET_TYPE_INGRESS);
	struct gadget_socket_value *skb_val =
		gadget_socket_lookup_with_direction(skb, is_ingress);

	struct packet_event_t *event;

	int zero = 0;
	event = bpf_map_lookup_elem(&tmp_packets, &zero);
	if (!event)
		return 0; // it never happens

	__builtin_memset(event, 0, sizeof(*event));

	__u64 len = skb->len;
	event->packet_size = len;

	if (len > snaplen)
		len = snaplen;

	event->payload_len = len;
	event->timestamp_raw = bpf_ktime_get_ns();
	event->ifindex = skb->ifindex;
	event->packet_type = packet_type;

	// Enrich event with process metadata
	gadget_process_populate_from_socket(skb_val, &event->proc);

	bpf_perf_event_output(skb, &packets, len << 32 | BPF_F_CURRENT_CPU,
			      event, sizeof(*event));
	return 0;
}

SEC("classifier/ingress/main")
int ingress_main(struct __sk_buff *skb)
{
	bpf_skb_pull_data(skb, 0);
	return handle(skb, PACKET_TYPE_INGRESS);
}

SEC("classifier/egress/main")
int egress_main(struct __sk_buff *skb)
{
	bpf_skb_pull_data(skb, 0);
	return handle(skb, PACKET_TYPE_EGRESS);
}

char _license[] SEC("license") = "GPL";
