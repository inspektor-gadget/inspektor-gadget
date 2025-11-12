// program.bpf.c

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/filter.h>
#include <gadget/filesystem.h>

struct event {
	__u32 foo;
	gadget_flex_string fname[255];
};

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(open, events, event);

SEC("tracepoint/syscalls/sys_enter_openat")
int enter_openat(struct syscall_trace_enter *ctx)
{
	if (gadget_should_discard_data_current())
		return 0;

	struct event *event;
	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	event->foo = 42;

	bool fname_exists = bpf_core_field_exists(event->fname);
	if (fname_exists) {
		char *fname = (char *)ctx->args[1];
		bpf_probe_read_user_str(
			event->fname, bpf_core_field_size(event->fname), fname);
	}

	unsigned int event_size = bpf_core_type_size(struct event);
	gadget_submit_buf(ctx, &events, event, event_size);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
