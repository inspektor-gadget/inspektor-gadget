// SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0
/* Copyright (c) 2023 The Inspektor Gadget authors */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

const volatile __u32 current_netns = 0;

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} tail_call SEC(".maps");

SEC("socket1")
int ig_net_disp(struct __sk_buff *skb)
{
	skb->cb[0] = current_netns;

	bpf_tail_call(skb, &tail_call, 0);

	return 0;
}

char _license[] SEC("license") = "GPL";
