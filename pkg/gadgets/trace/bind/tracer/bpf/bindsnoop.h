/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BINDSNOOP_H
#define __BINDSNOOP_H

#define TASK_COMM_LEN 16

struct bind_event {
	__u8 addr[16];
	__u64 mount_ns_id;
	__u64 timestamp;
	__u64 ts_us;
	__u32 pid;
	__u32 bound_dev_if;
	__u32 uid;
	__u32 gid;
	int ret;
	__u16 port;
	__u16 proto;
	__u8 opts;
	__u8 ver;
	__u8 task[TASK_COMM_LEN];
};

union bind_options {
	__u8 data;
	struct {
		__u8 freebind : 1;
		__u8 transparent : 1;
		__u8 bind_address_no_port : 1;
		__u8 reuseaddress : 1;
		__u8 reuseport : 1;
	} fields;
};


/*
 * Highly inspired from:
 * https://github.com/iovisor/bcc/pull/4846/commits/a55b5a0c920f
 */
struct inet_sock___o {
	__u8 freebind: 1;
	__u8 transparent: 1;
	__u8 bind_address_no_port: 1;
};

enum {
	INET_FLAGS_FREEBIND___x = 11,
	INET_FLAGS_TRANSPARENT___x = 15,
	INET_FLAGS_BIND_ADDRESS_NO_PORT___x = 18,
};

struct inet_sock___x {
	unsigned long inet_flags;
};

#define get_inet_sock_flag(inet_sock, flag_name, flag_value) ({                \
	__u8 __ret;                                                            \
	if (bpf_core_field_exists(struct inet_sock___o, flag_name)) {          \
		__ret = BPF_CORE_READ_BITFIELD_PROBED(                         \
			(struct inet_sock___o *)inet_sock, flag_name);         \
	} else {                                                               \
		unsigned long __flags;                                         \
		__flags = BPF_CORE_READ((struct inet_sock___x *)inet_sock,     \
				      inet_flags);                             \
		__ret = !!((1 << flag_value) & __flags);                       \
	}                                                                      \
	__ret; })

static __always_inline __u8 get_inet_sock_freebind(void *inet_sock)
{
	return get_inet_sock_flag(inet_sock, freebind, INET_FLAGS_FREEBIND___x);
}

static __always_inline __u8 get_inet_sock_transparent(void *inet_sock)
{
	return get_inet_sock_flag(inet_sock, transparent, INET_FLAGS_TRANSPARENT___x);
}

static __always_inline __u8 get_inet_sock_bind_address_no_port(void *inet_sock)
{
	return get_inet_sock_flag(inet_sock, bind_address_no_port, INET_FLAGS_BIND_ADDRESS_NO_PORT___x);
}

#endif /* __BINDSNOOP_H */
