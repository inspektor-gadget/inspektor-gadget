#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct map_test_struct {
	__u32 a;
	__u32 b;
	__u8 c;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(key_size, sizeof(struct map_test_struct));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 1024);
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_HASH);
			__uint(key_size, sizeof(u32));
			__uint(value_size, sizeof(u32));
			__uint(max_entries, 1);
		});
} map_of_map SEC(".maps");
