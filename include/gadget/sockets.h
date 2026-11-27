/* SPDX-License-Identifier: Apache-2.0 */

#ifndef __GADGET_SOCKETS_H
#define __GADGET_SOCKETS_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <gadget/types.h>

#ifndef NULL
#define NULL ((void *)0)
#endif

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

/*
 * gadget_l4endpoints_from_sock fills the src and/or dst gadget_l4endpoint_t
 * structures from a struct sock pointer.
 *
 * If src is non-NULL, it populates:
 *   - version (4 or 6)
 *   - addr_raw (local IP)
 *   - port (local port in host byte order)
 *   - proto_raw (IP protocol number)
 *
 * If dst is non-NULL, it populates:
 *   - version (4 or 6)
 *   - addr_raw (remote IP)
 *   - port (remote port in host byte order)
 *   - proto_raw (IP protocol number)
 *
 * Returns 0 on success, or -1 if the address family is unsupported.
 */
static __always_inline int
gadget_l4endpoints_from_sock(struct gadget_l4endpoint_t *src,
			     struct gadget_l4endpoint_t *dst,
			     const struct sock *sk)
{
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	__u16 proto = BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol);

	switch (family) {
	case AF_INET:
		if (src) {
			src->version = 4;
			BPF_CORE_READ_INTO(&src->addr_raw.v4, sk,
					   __sk_common.skc_rcv_saddr);
		}
		if (dst) {
			dst->version = 4;
			BPF_CORE_READ_INTO(&dst->addr_raw.v4, sk,
					   __sk_common.skc_daddr);
		}
		break;
	case AF_INET6:
		if (src) {
			src->version = 6;
			BPF_CORE_READ_INTO(
				&src->addr_raw.v6, sk,
				__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		}
		if (dst) {
			dst->version = 6;
			BPF_CORE_READ_INTO(
				&dst->addr_raw.v6, sk,
				__sk_common.skc_v6_daddr.in6_u.u6_addr32);
		}
		break;
	default:
		return -1;
	}

	if (src) {
		src->port = BPF_CORE_READ(sk, __sk_common.skc_num);
		if (src->port == 0) {
			struct inet_sock *sockp = (struct inet_sock *)sk;
			src->port = bpf_ntohs(BPF_CORE_READ(sockp, inet_sport));
		}
		src->proto_raw = proto;
	}
	if (dst) {
		dst->port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
		dst->proto_raw = proto;
	}

	return 0;
}

/*
 * gadget_l4endpoint_src_from_sock fills only the source (local) endpoint
 * from struct sock.
 */
static __always_inline int
gadget_l4endpoint_src_from_sock(struct gadget_l4endpoint_t *src,
				const struct sock *sk)
{
	return gadget_l4endpoints_from_sock(src, NULL, sk);
}

/*
 * gadget_l4endpoint_dst_from_sock fills only the destination (remote) endpoint
 * from struct sock.
 */
static __always_inline int
gadget_l4endpoint_dst_from_sock(struct gadget_l4endpoint_t *dst,
				const struct sock *sk)
{
	return gadget_l4endpoints_from_sock(NULL, dst, sk);
}

#endif /* __GADGET_SOCKETS_H */
