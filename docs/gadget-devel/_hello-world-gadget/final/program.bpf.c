// Kernel types definitions
// Check https://blog.aquasec.com/vmlinux.h-ebpf-programs for more details
#include <vmlinux.h>

// eBPF helpers signatures
// Check https://man7.org/linux/man-pages/man7/bpf-helpers.7.html to learn
// more about different available helpers
#include <bpf/bpf_helpers.h>

// Inspektor Gadget buffer
#include <gadget/buffer.h>

// Helpers to handle common data
#include <gadget/common.h>

// Inspektor Gadget macros
#include <gadget/macros.h>

// Inspektor Gadget filtering
#include <gadget/filter.h>

// Inspektor Gadget types
#include <gadget/types.h>

#define NAME_MAX 255

struct event {
	struct gadget_process proc;

	char filename[NAME_MAX];
};

// events is the name of the buffer map and 1024 * 256 is its size.
GADGET_TRACER_MAP(events, 1024 * 256);

// [Optional] Define a tracer
GADGET_TRACER(open, events, event);

SEC("tracepoint/syscalls/sys_enter_openat")
int enter_openat(struct syscall_trace_enter *ctx)
{
	struct event *event;

	if (gadget_should_discard_data_current())
		return 0;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	gadget_process_populate(&event->proc);
	bpf_probe_read_user_str(event->filename, sizeof(event->filename),
				(const char *)ctx->args[1]);

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
