#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#define NAME_MAX 255

struct event {
	__u32 pid;
	__u8 comm[TASK_COMM_LEN];
	__u8 filename[NAME_MAX];
};

// we need this to make sure the compiler doesn't remove our struct
const struct event *unusedevent __attribute__((unused));

// map used to test that a wrong map type can't be used
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct event);
	__type(value, __u8);
} events SEC(".maps");

GADGET_TRACE_MAP(events);

char LICENSE[] SEC("license") = "GPL";
