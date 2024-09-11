// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 The Inspektor Gadget authors */

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/filesystem.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#include "go-utils.h"

#define PKTLEN 2048

enum op {
	WRITE,
	READ,
};

struct event {
    enum op op_raw;
    __u64 len;
    char buf[PKTLEN];
};

struct tlsinfo {
    __u64 tls;
    __u64 buf_ptr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct tlsinfo);
} scratch SEC(".maps");

GADGET_TRACER_MAP(events, 4096*4096); // 4096 in-flight pages
GADGET_TRACER(raw, events, event);

SEC("uprobe//worker:crypto/tls.(*Conn).Write")
int uprobe_write(struct pt_regs *ctx) {
    __u64 buf_ptr = (__u64)GO_PARAM2(ctx);
    __u32 len = (__u64)GO_PARAM3(ctx);

    if (len == 0) return 0;

    struct event *event;

    __u32 remaining = len;
    __u32 curlen = 0;
    __u32 offs = 0;

    for (int i = 0; i < 64; i++) {
        curlen = remaining;
        if (curlen > PKTLEN) {
            curlen = PKTLEN;
        }
        event = gadget_reserve_buf(&events, sizeof(*event));
        if (!event)
            break;

        event->op_raw = WRITE;
        bpf_probe_read_user(&event->buf[0], curlen, (unsigned char*)(buf_ptr)+offs);
        gadget_submit_buf(ctx, &events, event, sizeof(*event));
        remaining -= curlen;
        offs += curlen;
        if (remaining == 0) break;
    }

    return 0;
}

SEC("uprobe//worker:crypto/tls.(*Conn).Read")
int uprobe_read(struct pt_regs *ctx) {
    __u64 goroutine_addr = (__u64)GOROUTINE_PTR(ctx);

    struct tlsinfo tlsinfo = {
        .tls = (__u64)GO_PARAM1(ctx),
        .buf_ptr = (__u64)GO_PARAM2(ctx),
    };

    bpf_map_update_elem(&scratch, &goroutine_addr, &tlsinfo, BPF_ANY);
    return 0;
}

SEC("uretprobe//worker:crypto/tls.(*Conn).Read")
int uretprobe_read(struct pt_regs *ctx) {
    __u32 len = (__u64)GO_PARAM1(ctx);

    __u64 goroutine_addr = (__u64)GOROUTINE_PTR(ctx);

    struct tlsinfo* tlsinfo = bpf_map_lookup_elem(&scratch, &goroutine_addr);
    if (!tlsinfo) {
        return 0;
    }

    bpf_map_delete_elem(&scratch, &goroutine_addr);

    if (len == 0) return 0;

    struct event *event;

    __u32 remaining = len;
    __u32 curlen = 0;
    __u32 offs = 0;

    for (int i = 0; i < 64; i++) {
        curlen = remaining;
        if (curlen > PKTLEN) {
            curlen = PKTLEN;
        }
        event = gadget_reserve_buf(&events, sizeof(*event));
        if (!event) {
            break;
        }

        event->op_raw = READ;
        event->len = curlen;
        bpf_probe_read_user(&event->buf[0], curlen, (unsigned char*)(tlsinfo->buf_ptr)+offs);
        gadget_submit_buf(ctx, &events, event, sizeof(*event));
        remaining -= curlen;
        offs += curlen;
        if (remaining == 0) break;
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
