// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 The Inspektor Gadget authors */

#ifndef GADGET_NETWORK_GRAPH_GRAPHMAP_H
#define GADGET_NETWORK_GRAPH_GRAPHMAP_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "graph.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct graph_key_t);
	__type(value, u64); // timestamp
} graphmap SEC(".maps");

#endif
