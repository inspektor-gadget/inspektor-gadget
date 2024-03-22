#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include <gadget/macros.h>

struct hist_key {
	__u32 cmd_flags;
	__u32 dev;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct hist_key);
	__type(value, struct hist_value);
} hists SEC(".maps");

GADGET_PROFILER(test, hists, hist_key);

char LICENSE[] SEC("license") = "GPL";
