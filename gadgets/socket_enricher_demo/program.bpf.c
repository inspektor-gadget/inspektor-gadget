// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021-2022 The Inspektor Gadget authors */
/* Copyright (c) 2021-2022 SAP SE or an SAP affiliate company and Gardener contributors */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

//#define GADGET_NO_BUF_RESERVE
//#define MAX_EVENT_SIZE 512
#define GADGET_TYPE_NETWORKING
#include <gadget/macros.h>
#include <gadget/buffer.h>
#include <gadget/types.h>
#include <gadget/sockets-map.h>
#include <gadget/filter.h>
#include <linux/pkt_cls.h>

#define SK_ALLOW 1

struct event_t {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;
};

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(sni, events, event_t);

static inline void process(struct __sk_buff *skb)
{
	struct event_t event = {
		0,
	};

	struct sockets_value *skb_val = gadget_socket_lookup(skb);
	//if (gadget_should_discard_data_by_skb(skb_val))
	//	return;

	event.timestamp_raw = bpf_ktime_get_boot_ns();

	// Enrich event with process metadata
	gadget_process_populate_from_socket(skb_val, &event.proc);

	gadget_output_buf(skb, &events, &event, sizeof(event));
}

//SEC("cgroup_skb/egress")
//int demo_egress(struct __sk_buff *skb)
//{
//	process(skb);
//	return SK_ALLOW;
//}
//
//SEC("cgroup_skb/ingress")
//int demo_ingress(struct __sk_buff *skb)
//{
//	process(skb);
//	return SK_ALLOW;
//}


//SEC("classifier/egress/drop")
//int egress_drop(struct __sk_buff *skb) {
//	process(skb);
//	return TC_ACT_UNSPEC;
//}
//
//SEC("classifier/ingress/drop")
//int ingress_drop(struct __sk_buff *skb) {
//	process(skb);
//	return TC_ACT_UNSPEC;
//}

SEC("socket1")
int ig_trace_dns(struct __sk_buff *skb)
{
	process(skb);
	return 0;
}


char _license[] SEC("license") = "GPL";
