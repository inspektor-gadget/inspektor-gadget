/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0 */

#ifndef GADGET_TRACER_MANAGER_MAPS_H
#define GADGET_TRACER_MANAGER_MAPS_H

#include "common.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct container);
	__uint(max_entries, MAX_CONTAINERS_PER_NODE);
} containers SEC(".maps");

#ifdef WITH_FILTER
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u32);
	__uint(max_entries, MAX_CONTAINERS_PER_NODE);
} filter SEC(".maps");
#endif

#endif
