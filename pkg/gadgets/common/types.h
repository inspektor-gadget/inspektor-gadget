/* SPDX-License-Identifier: Apache-2.0 */

#ifndef __TYPES_H
#define __TYPES_H

// Keep these types aligned with definitions in pkg/gadgets/run/tracer/tracer.go.

// union defining either an IPv4 or IPv6 address
union gadget_ip_addr_t {
	__u8 v6[16];
	__u32 v4;
};

// struct defining either an IPv4 or IPv6 L3 endpoint
struct gadget_l3endpoint_t {
	union gadget_ip_addr_t addr;
	__u8 version; // 4 or 6
	__u8 pad[3]; // manual padding to avoid issues between C and Go
};

// struct defining an L4 endpoint
struct gadget_l4endpoint_t {
	struct gadget_l3endpoint_t l3;
	__u16 port;
	__u16 proto; // IP protocol number
};

// Inode id of a mount namespace. It's used to enrich the event in user space
typedef __u64 mnt_ns_id_t;

#endif /* __TYPES_H */
