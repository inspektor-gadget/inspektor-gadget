/* SPDX-License-Identifier: Apache-2.0 */

#ifndef __TYPES_H
#define __TYPES_H

// union defining either IPv4 or IPv6 address
union ip_addr {
	__u8 v6[16];
	__u32 v4;
};

// Inode id of a mount namespace. It's used to enrich the event in user space
typedef u64 mnt_ns_id_t;

#endif /* __TYPES_H */
