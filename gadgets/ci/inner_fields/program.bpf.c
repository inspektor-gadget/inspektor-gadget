#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/types.h>

enum myenum {
	ONE = 1,
	TWO = 2,
	THREE = 3,
};

// Just to show inner fields
struct inner {
	gadget_uid inner_user_raw;
	gadget_gid inner_group_raw;
	gadget_syscall inner_syscall_raw;
	gadget_errno inner_errno_raw;
	enum myenum inner_enum_raw;
};

struct event {
	gadget_uid user_raw;
	gadget_gid group_raw;
	gadget_syscall syscall_raw;
	gadget_errno errno_raw;
	enum myenum enum_raw;

	struct inner inner;
};

GADGET_TRACER_MAP(open_events, 1024 * 256);
GADGET_TRACER(open, open_events, event);

SEC("tracepoint/syscalls/sys_enter_openat")
int enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *event;

	event = gadget_reserve_buf(&open_events, sizeof(*event));
	if (!event)
		return 0;

	event->user_raw = 0;
	event->group_raw = 0;
	event->syscall_raw = 50;
	event->errno_raw = 15;
	event->enum_raw = TWO;

	event->inner.inner_user_raw = event->user_raw;
	event->inner.inner_group_raw = event->group_raw;
	event->inner.inner_syscall_raw = event->syscall_raw;
	event->inner.inner_errno_raw = event->errno_raw;
	event->inner.inner_enum_raw = event->enum_raw;

	gadget_submit_buf(ctx, &open_events, event, sizeof(*event));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
