/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0 */

#ifndef SOCKET_ENRICHER_HELPERS_H
#define SOCKET_ENRICHER_HELPERS_H

#include <vmlinux/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

static __always_inline void prepare_socket_key(struct sockets_key *socket_key,
					       struct sock *sock)
{
	struct inet_sock *inet_sock = (struct inet_sock *)sock;
	BPF_CORE_READ_INTO(&socket_key->netns, sock, __sk_common.skc_net.net,
			   ns.inum);
	BPF_CORE_READ_INTO(&socket_key->family, sock, __sk_common.skc_family);
	socket_key->proto = BPF_CORE_READ_BITFIELD_PROBED(sock, sk_protocol);
	socket_key->port = bpf_ntohs(BPF_CORE_READ(inet_sock, inet_sport));
}

#endif
