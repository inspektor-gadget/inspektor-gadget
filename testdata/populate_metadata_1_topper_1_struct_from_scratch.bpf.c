#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include <gadget/macros.h>

#define NAME_MAX 255

struct event {
	__u32 pid;
	__u8 comm[TASK_COMM_LEN];
	__u8 filename[NAME_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct event);
} events SEC(".maps");

GADGET_TOPPER(my_topper, events);

char LICENSE[] SEC("license") = "GPL";
