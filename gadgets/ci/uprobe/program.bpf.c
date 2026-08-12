// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/types.h>

#if defined(__TARGET_ARCH_x86)
#define GO_PARAM1(ctx) ((void *)(ctx)->ax)
#define GO_PARAM2(ctx) ((void *)(ctx)->bx)
#elif defined(__TARGET_ARCH_arm64)
#define GO_PARAM1(ctx) ((void *)((struct pt_regs *)(ctx))->user_regs.regs[0])
#define GO_PARAM2(ctx) ((void *)((struct pt_regs *)(ctx))->user_regs.regs[1])
#else
#error "unsupported architecture"
#endif

/*
 * Please keep the Go versions and build modes in sync with:
 * - workload/Dockerfile
 * - test/integration/ci_uprobe_test.go
 */
#define FOR_EACH_GO_TARGET(F)                                           \
	F("/opt/ig-tests/ci-uprobe/go1.25/normal/target", GO125_NORMAL) \
	F("/opt/ig-tests/ci-uprobe/go1.25/pie/target", GO125_PIE)       \
	F("/opt/ig-tests/ci-uprobe/go1.25/linker/target", GO125_LINKER) \
	F("/opt/ig-tests/ci-uprobe/go1.25/strip/target", GO125_STRIP)   \
	F("/opt/ig-tests/ci-uprobe/go1.26/normal/target", GO126_NORMAL) \
	F("/opt/ig-tests/ci-uprobe/go1.26/pie/target", GO126_PIE)       \
	F("/opt/ig-tests/ci-uprobe/go1.26/linker/target", GO126_LINKER) \
	F("/opt/ig-tests/ci-uprobe/go1.26/strip/target", GO126_STRIP)

enum go_target_variant {
#define DECLARE_GO_TARGET(path, variant) variant,
	FOR_EACH_GO_TARGET(DECLARE_GO_TARGET)
#undef DECLARE_GO_TARGET
};

struct event {
	struct gadget_process proc;
	enum go_target_variant variant_raw;
	char name[128];
};

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(go_uprobe, events, event);

static __always_inline int trace_go_target(struct pt_regs *ctx,
					   enum go_target_variant variant)
{
	struct event *event;
	__u64 len;

	if (gadget_should_discard_data_current())
		return 0;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	gadget_process_populate(&event->proc);
	event->variant_raw = variant;

	/*
	 * Go strings are not NUL terminated: the data pointer is passed in the
	 * first argument register and the length in the second one.
	 */
	len = (__u64)GO_PARAM2(ctx);
	if (len > sizeof(event->name) - 1)
		len = sizeof(event->name) - 1;
	event->name[len] = '\0';
	if (bpf_probe_read_user(event->name, len, GO_PARAM1(ctx)) < 0)
		event->name[0] = '\0';

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

#define DECLARE_GO_UPROBE(path, variant)                   \
	SEC("uprobe/" path ":main.target")                 \
	int trace_go_target_##variant(struct pt_regs *ctx) \
	{                                                  \
		return trace_go_target(ctx, variant);      \
	}

FOR_EACH_GO_TARGET(DECLARE_GO_UPROBE)

char LICENSE[] SEC("license") = "Dual BSD/GPL";
