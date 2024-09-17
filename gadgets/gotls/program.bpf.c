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

#undef bpf_printk
#define bpf_printk(fmt, ...)                            \
({                                                      \
        static const char ____fmt[] = fmt;              \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})


struct pt_regs;
#define PT_REGS_ARM64 const volatile struct user_pt_regs

#define __TARGET_ARCH_arm64 1
#if defined(__TARGET_ARCH_x86)

#define GO_PARAM1(x) ((void*)(x)->ax)
#define GO_PARAM2(x) ((void*)(x)->bx)
#define GO_PARAM3(x) ((void*)(x)->cx)
#define GO_PARAM4(x) ((void*)(x)->di)
#define GO_PARAM5(x) ((void*)(x)->si)
#define GO_PARAM6(x) ((void*)(x)->r8)
#define GO_PARAM7(x) ((void*)(x)->r9)
#define GO_PARAM8(x) ((void*)(x)->r10)
#define GO_PARAM9(x) ((void*)(x)->r11)

// In x86, current goroutine is pointed by r14, according to
// https://go.googlesource.com/go/+/refs/heads/dev.regabi/src/cmd/compile/internal-abi.md#amd64-architecture
#define GOROUTINE_PTR(x) ((void*)(x)->r14)

#elif defined(__TARGET_ARCH_arm64)

#define GO_PARAM1(x) ((void*)((PT_REGS_ARM64 *)(x))->regs[0])
#define GO_PARAM2(x) ((void*)((PT_REGS_ARM64 *)(x))->regs[1])
#define GO_PARAM3(x) ((void*)((PT_REGS_ARM64 *)(x))->regs[2])
#define GO_PARAM4(x) ((void*)((PT_REGS_ARM64 *)(x))->regs[3])
#define GO_PARAM5(x) ((void*)((PT_REGS_ARM64 *)(x))->regs[4])
#define GO_PARAM6(x) ((void*)((PT_REGS_ARM64 *)(x))->regs[5])
#define GO_PARAM7(x) ((void*)((PT_REGS_ARM64 *)(x))->regs[6])
#define GO_PARAM8(x) ((void*)((PT_REGS_ARM64 *)(x))->regs[7])
#define GO_PARAM9(x) ((void*)((PT_REGS_ARM64 *)(x))->regs[8])
#define GO_PARAM10(x) ((void*)((PT_REGS_ARM64 *)(x))->regs[9])
#define GO_PARAM11(x) ((void*)((PT_REGS_ARM64 *)(x))->regs[10])
#define GO_PARAM12(x) ((void*)((PT_REGS_ARM64 *)(x))->regs[11])
#define GO_PARAM13(x) ((void*)((PT_REGS_ARM64 *)(x))->regs[12])

// In arm64, current goroutine is pointed by R28 according to
// https://github.com/golang/go/blob/master/src/cmd/compile/abi-internal.md#arm64-architecture
#define GOROUTINE_PTR(x) ((void*)((PT_REGS_ARM64 *)(x))->regs[28])

#endif /*defined(__TARGET_ARCH_arm64)*/

#define PKTLEN 2048

struct event {
    __u64 fd;
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

SEC("uprobe//gofetch:crypto/tls.(*Conn).Write")
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

        event->len = curlen;
        bpf_probe_read_user(&event->buf[0], curlen, (unsigned char*)(buf_ptr)+offs);
        gadget_submit_buf(ctx, &events, event, sizeof(*event));
        remaining -= curlen;
        offs += curlen;
        if (remaining == 0) break;
    }

    return 0;
}

SEC("uprobe//gofetch:crypto/tls.(*Conn).Read")
int uprobe_read(struct pt_regs *ctx) {
    __u64 goroutine_addr = (__u64)GOROUTINE_PTR(ctx);

    struct tlsinfo tlsinfo = {
        .tls = (__u64)GO_PARAM1(ctx),
        .buf_ptr = (__u64)GO_PARAM2(ctx),
    };

    bpf_map_update_elem(&scratch, &goroutine_addr, &tlsinfo, BPF_ANY);
    return 0;
}

SEC("uretprobe//gofetch:crypto/tls.(*Conn).Read")
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

        event->fd = tlsinfo->tls;
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
