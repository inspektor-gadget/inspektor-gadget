#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include <gadget/macros.h>

#define NAME_MAX 255

struct event {
	__u32 pid;
	__u8 comm[TASK_COMM_LEN];
	__u8 filename[NAME_MAX];
};

GADGET_SNAPSHOTTER(events, event);

char LICENSE[] SEC("license") = "GPL";
