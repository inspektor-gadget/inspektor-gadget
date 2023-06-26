/* SPDX-License-Identifier: Apache-2.0 */

#ifndef __TYPES_H
#define __TYPES_H

// union defining either an IPv4 or IPv6 address
union gadget_ip_addr_t {
	__u8 v6[16];
	__u32 v4;
};

// struct defining either an IPv4 or IPv6 endpoint
struct gadget_endpoint_t {
	union gadget_ip_addr_t addr;
	__u16 port;
	__u8 version; // 4 or 6
};

// Inode id of a mount namespace. It's used to enrich the event in user space
typedef u64 mnt_ns_id_t;

#endif /* __TYPES_H */
