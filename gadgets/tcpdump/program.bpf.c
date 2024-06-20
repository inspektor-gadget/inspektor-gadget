// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 The Inspektor Gadget authors */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <sys/socket.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/types.h>

#define GADGET_TYPE_NETWORKING
#include <gadget/sockets-map.h>

// TODO: what's a reasonable value for this?
// Or can we remove this altogether?
#define MAX_PACKET (1024*9) // 9KB

#define TASK_COMM_LEN 16

struct event_t {
    gadget_timestamp timestamp;

	//struct gadget_l4endpoint_t src;
	//struct gadget_l4endpoint_t dst;
    gadget_mntns_id mntns_id;
    gadget_netns_id netns;
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 gid;
	char task[TASK_COMM_LEN];

    __u32 len;

    // raw contents of the packet
    __u8 data[MAX_PACKET];
};

// TODO: We need this header structure as the packet itself is appended by
// bpf_perf_event_output(). Hence the even we send over the perf ring buffer is
// only the header without the packet. We can use the full structure above as
// it exceeds the stack limit of 512 bytes in bpf.
// TODO: We'll need to find a clearer way to implement this
struct event_header {
    gadget_timestamp timestamp;

	//struct gadget_l4endpoint_t src;
	//struct gadget_l4endpoint_t dst;

    gadget_mntns_id mntns_id;
    gadget_netns_id netns;
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 gid;
	char task[TASK_COMM_LEN];

    __u32 len;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

GADGET_TRACER(tcpdump, events, event_t);

SEC("socket1")
int ig_tcpdump(struct __sk_buff *skb)
{
    __u64 skb_len = skb->len;
    // TODO: probably not needed, but better to be safe
    if (skb_len > MAX_PACKET)
        return 0;

    struct event_header event = {};
    event.timestamp = bpf_ktime_get_boot_ns();
    event.netns = skb->cb[0]; // cb[0] initialized by dispatcher.bpf.c
    event.len = skb_len;

	// Enrich event with process metadata
	struct sockets_value *skb_val = gadget_socket_lookup(skb);
	if (skb_val != NULL) {
		//event.mntns_id = skb_val->mntns;
		event.pid = skb_val->pid_tgid >> 32;
		event.tid = (__u32)skb_val->pid_tgid;
		__builtin_memcpy(&event.task, skb_val->task,
				 sizeof(event.task));
		event.uid = (__u32)skb_val->uid_gid;
		event.gid = (__u32)(skb_val->uid_gid >> 32);
	}

    // skb_len << 32 means to append the skb to the event, so the skb is data in
    // the event_t structure
	bpf_perf_event_output(skb, &events, skb_len << 32 | BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

    return 0;
}

char _license[] SEC("license") = "GPL";
