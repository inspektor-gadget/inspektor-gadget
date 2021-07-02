#ifndef GADGET_TRACER_MANAGER_MAPS_H
#define GADGET_TRACER_MANAGER_MAPS_H

struct ns_common {
	unsigned int inum;
} __attribute__((preserve_access_index));

struct mnt_namespace {
	struct ns_common ns;
}__attribute__((preserve_access_index));

// struct container needs to be kept in sync with the same struct from
// pkg/gadgettracermanager/gadgettracermanager.go
struct container {
	char container_id[256];
	char kubernetes_namespace[256];
	char kubernetes_pod[256];
	char kubernetes_container[256];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct container);
	__uint(max_entries, 1024);
} containers SEC(".maps");

#ifdef WITH_FILTER
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u32);
	__uint(max_entries, 10240);
} filter SEC(".maps");
#endif

#endif
