#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include <gadget/macros.h>

// map used to test wrong value type
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__type(value, sizeof(u32));
} events SEC(".maps");

GADGET_TRACE_MAP(events);

char LICENSE[] SEC("license") = "GPL";
