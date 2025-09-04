#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/macros.h>
#include <gadget/filter.h>
#include <gadget/types.h>

struct event {
	struct gadget_process proc;
};

GADGET_TRACER_MAP(open_events, 1024 * 256);
GADGET_TRACER(open, open_events, event);

SEC("tracepoint/syscalls/sys_enter_openat")
int enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *event;

	if (gadget_should_discard_data_current())
		return 0;

	event = gadget_reserve_buf(&open_events, sizeof(*event));
	if (!event)
		return 0;

	gadget_process_populate(&event->proc);

	gadget_submit_buf(ctx, &open_events, event, sizeof(*event));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
