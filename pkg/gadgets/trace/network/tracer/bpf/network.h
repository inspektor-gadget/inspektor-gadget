// SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0
/* Copyright (c) 2023 The Inspektor Gadget authors */

#ifndef GADGET_NETWORK_H
#define GADGET_NETWORK_H

struct event_t {
	// Keep netns at the top: networktracer depends on it
	__u32 netns;

	__u64 timestamp;
	__u64 mount_ns_id;
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 gid;
	__u8 task[TASK_COMM_LEN];

	__u32 pkt_type;
	__u32 ip;
	__u16 proto;
	__u16 port;
};

#endif
