// SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0
/* Copyright (c) 2021 The Inspektor Gadget authors */

#include <vmlinux/vmlinux.h>

#include <bpf/bpf_helpers.h>

#include "gadgettracermanager/common.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct container);
	__uint(max_entries, MAX_CONTAINERS_PER_NODE);
} containers SEC(".maps");

char _license[] SEC("license") = "GPL";
