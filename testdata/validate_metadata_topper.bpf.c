#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include <gadget/macros.h>
#include <gadget/types.h>

#define NAME_MAX 255

struct event {
	gadget_mntns_id mntns_id;
	__u32 pid;
	__u8 comm[TASK_COMM_LEN];
	__u8 filename[NAME_MAX];
};
struct event *unusedevent __attribute__((unused));

// struct used to check a topper that has a wrong struct name in the metadata
struct event2 {
	gadget_mntns_id mntns_id;
};
struct event2 *unusedevent2 __attribute__((unused));

// map used to test good map
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, gadget_mntns_id);
	__type(value, struct event);
} myhashmap SEC(".maps");

// map used to test wrong value type
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__type(value, struct event);
} events SEC(".maps");

// map used to test wrong value type
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, gadget_mntns_id);
	__type(value, __u32);
} hash_wrong_value_map SEC(".maps");

// map used to test map without BTF
// TODO: It's probably that this support will be removed from ebpf library as it was done in libbpf
// (https://github.com/libbpf/libbpf/issues/272) at that time we'll need to remove it.
struct {
	unsigned int type;
	__u32 *key;
	struct event *value;
} hash_without_btf SEC("maps") = {
	.type = BPF_MAP_TYPE_HASH,
};

char LICENSE[] SEC("license") = "GPL";
