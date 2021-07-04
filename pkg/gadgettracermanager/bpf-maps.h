#ifndef GADGET_TRACER_MANAGER_MAPS_H
#define GADGET_TRACER_MANAGER_MAPS_H

#include "common.h"

struct ns_common {
	unsigned int inum;
} __attribute__((preserve_access_index));

struct mnt_namespace {
	struct ns_common ns;
}__attribute__((preserve_access_index));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct container);
	__uint(max_entries, MAX_CONTAINER_PER_NODE);
} containers SEC(".maps");

#ifdef WITH_FILTER
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u32);
	__uint(max_entries, MAX_CONTAINER_PER_NODE);
} filter SEC(".maps");
#endif

#endif
