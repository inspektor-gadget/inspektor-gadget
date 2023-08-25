/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0 */

#ifndef CGROUP_FILTER_H
#define CGROUP_FILTER_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define CGROUP_ENTRIES 2048

const volatile bool gadget_filter_by_cgroup = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u8);
	__uint(max_entries, CGROUP_ENTRIES);
} gadget_cgroup_filter_map SEC(".maps");

// gadget_should_discard_cgroup_id returns true if events generated from the given cgroup_id should
// not be taken into consideration.
static __always_inline bool gadget_should_discard_cgroup_id(__u64 cgroup_id) {
	return gadget_filter_by_cgroup && !bpf_map_lookup_elem(&gadget_cgroup_filter_map, &cgroup_id);
}

#endif
