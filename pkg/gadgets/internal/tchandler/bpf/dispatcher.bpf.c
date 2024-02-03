// SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0
/* Copyright (c) 2024 The Inspektor Gadget authors */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>

const volatile __u32 current_netns = 0;

// Keep in sync with dispatcherMapSpec in tracer.go
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} gadget_tail_call SEC(".maps");

SEC("classifier/dispatcher")
int ig_net_disp(struct __sk_buff *skb)
{
	skb->cb[0] = current_netns;
	bpf_tail_call(skb, &gadget_tail_call, 0);
	return TC_ACT_UNSPEC; // Use the default action configured from tc.
}

char _license[] SEC("license") = "GPL";
