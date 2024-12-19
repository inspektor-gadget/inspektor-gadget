// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include <gadget/common.h>
#include <gadget/mntns_filter.h>
#include <gadget/filesystem.h>
#include <gadget/types.h>
#include <gadget/macros.h>

#define TAIL_CALL_PROG_INDEX 0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} filterprog SEC(".maps");

#define GADGET_BPF_FILTER(name, mapname) \
	const void *gadget_bpf_filter_##name##___##mapname __attribute__((unused));

GADGET_BPF_FILTER(filter, filterprog)

__attribute__((noinline)) int filterfunc(struct __sk_buff *skb)
{
    volatile int ret = skb != NULL;
    return ret;
}

SEC("socket1")
int main_prog(struct __sk_buff *skb)
{
    bpf_printk("in main");
    if (filterfunc(skb) == 0) {
        return 0;
    }
    // bpf_tail_call(skb, &filterprog, TAIL_CALL_PROG_INDEX);
    return 0;
}

SEC("socket1/filter/filter/ok")
int gfilter_ok(struct __sk_buff *skb)
{
    bpf_printk("filter ok");
    return 0;
}

SEC("socket1/filter/filter/nok")
int gfilter_nok(struct __sk_buff *skb)
{
    bpf_printk("filter nok");
    return 0;
}

SEC("freplace/filterfunc")
int subprogrepl(struct __sk_buff *skb)
{
    return 0;
}

char _license[] SEC("license") = "GPL";