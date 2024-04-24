#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include <gadget/macros.h>

#define NAME_MAX 255

struct event {
	__u32 pid;
	__u8 comm[TASK_COMM_LEN];
	__u8 filename[NAME_MAX];
};

GADGET_SNAPSHOTTER(events, event, ig_snap_proc);

SEC("iter/task")
int ig_snap_proc(struct bpf_iter__task *ctx)
{
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
