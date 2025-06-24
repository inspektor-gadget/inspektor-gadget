// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 The Inspektor Gadget authors */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <gadget/macros.h>

const volatile int iface = -1;
GADGET_PARAM(iface);

const volatile int ppid = 0;
GADGET_PARAM(ppid);

const volatile int pid = 10;
GADGET_PARAM(pid);

SEC("classifier/egress/drop")
int egress_drop(struct __sk_buff *skb)
{
	return TC_ACT_SHOT;
}

SEC("classifier/ingress/drop")
int ingress_drop(struct __sk_buff *skb)
{
	return TC_ACT_SHOT;
}

char __license[] SEC("license") = "GPL";
