#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include <gadget/macros.h>

#define NAME_MAX 255

struct event {
	__u32 pid;
	__u8 comm[TASK_COMM_LEN];
	__u8 filename[NAME_MAX];
};

// map used to test map without BTF
// TODO: It's probably that this support will be removed from ebpf library as it was done in libbpf
// (https://github.com/libbpf/libbpf/issues/272) at that time we'll need to remove it.
struct {
	unsigned int type;
	__u32 *key;
	struct event *value;
} events SEC("maps") = {
	.type = BPF_MAP_TYPE_HASH,
};

GADGET_TOPPER(test, events);

char LICENSE[] SEC("license") = "GPL";
