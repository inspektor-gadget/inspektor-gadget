#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct event {
	__u32 a;
	__u32 b;
	__u8 c;
	__u8 unused[247];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_write")
int test_write_e(struct syscall_trace_enter *ctx)
{
	struct event event = { .a = 42, .b = 42, .c = 43 };

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
			      sizeof(event));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
