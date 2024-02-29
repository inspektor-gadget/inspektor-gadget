#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include <gadget/macros.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
} events SEC(".maps");

GADGET_TOPPER(my_topper, events);

char LICENSE[] SEC("license") = "GPL";
