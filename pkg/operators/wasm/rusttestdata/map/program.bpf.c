#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct map_test_struct {
	__u32 a;
	__u32 b;
	__u8 c;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, struct map_test_struct);
	__type(value, __u32);
} test_map SEC(".maps");
