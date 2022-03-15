// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 The Inspektor Gadget authors */

#ifndef GADGET_NETWORK_GRAPH_H
#define GADGET_NETWORK_GRAPH_H

#include "../../../../vmlinux/vmlinux-cgo.h"

#define MAX_ENTRIES	10240

struct graph_key_t {
	u64 container_quark;
	u32 pkt_type;
	u32 ip;
	u16 proto;
	u16 port;
};

#endif
