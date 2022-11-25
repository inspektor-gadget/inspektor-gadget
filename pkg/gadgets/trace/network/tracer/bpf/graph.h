// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 The Inspektor Gadget authors */

#ifndef GADGET_NETWORK_GRAPH_H
#define GADGET_NETWORK_GRAPH_H

#ifdef __TARGET_ARCH_arm64
#include "../../../../../arm64/vmlinux/vmlinux-cgo.h"
#else
// In several case (e.g. make test), we compile this file without having set
// BPF_ARCH, so we default to include amd64 vmlinux.h.
// For other architecture, like arm64, we use __TARGET_ARCH_arch to
// differentiate.
#include "../../../../../amd64/vmlinux/vmlinux-cgo.h"
#endif

#define MAX_ENTRIES	10240

struct graph_key_t {
	u64 container_netns;
	u32 pkt_type;
	u32 ip;
	u16 proto;
	u16 port;
};

#endif
