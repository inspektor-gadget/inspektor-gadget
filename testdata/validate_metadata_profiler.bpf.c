#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include <gadget/macros.h>
#include <gadget/types.h>

#define MAX_ENTRIES 16

struct hist_key {
	__u32 cmd_flags;
	__u32 dev;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct hist_key);
	__type(value, struct hist_value);
} hists SEC(".maps");

struct event {
	gadget_mntns_id mntns_id;
	__u32 pid;
	__u8 comm[TASK_COMM_LEN];
	__u8 filename[NAME_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__type(value, struct event);
} events SEC(".maps");

GADGET_PROFILER(profiler, hists, hist_key);

char LICENSE[] SEC("license") = "GPL";
