/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0 */
/* Copyright (c) 2026 The Inspektor Gadget authors */

/*
 * Reusable plumbing for gadgets that observe TCP-stream application protocols
 * (DNS-over-TCP, HTTP, ...) using the sock_ops + sk_skb + sk_msg program types.
 *
 * For a full walkthrough see the developer guide:
 * https://www.inspektor-gadget.io/docs/latest/gadget-devel/tcp-stream-gadgets
 *
 * The pattern is:
 *
 *   sock_ops (on TCP connect/established)
 *                    ->  insert the socket into gadget_sockhash and record its
 *                        4-tuple and process info in the connection tables,
 *                        indexed by socket cookie (gadget_tcp_stream_conns) and
 *                        by 4-tuple (gadget_tcp_stream_tuples)
 *                                              |
 *                    +-------------------------+-------------------------+
 *                    |                                                   |
 *   sk_skb STREAM_VERDICT (receive path)              sk_msg (send path)
 *     runs on the reassembled TCP stream                runs on sent stream data
 *     of sockets in gadget_sockhash;                    of sockets in gadget_sockhash;
 *     recover the connection via                        recover the connection via
 *     gadget_tcp_stream_lookup(skb).                    gadget_tcp_stream_msg_lookup(msg).
 *
 * A gadget only needs to:
 *   1. #include <gadget/tcp_stream.h>
 *   2. (optionally) #define gadget_tcp_stream_should_track(skops) to restrict
 *      which sockets are tracked (e.g. by port), BEFORE including this header.
 *   3. Write a SEC("sk_skb/stream_verdict") program that parses received data
 *      and returns SK_PASS. Use gadget_tcp_stream_lookup(skb) to get the
 *      connection (tuple + process enrichment).
 *   4. (optionally, but recommended) Write a SEC("sk_skb/stream_parser")
 *      program that returns the length of the next complete application
 *      message. When present, the kernel's stream parser (strparser) buffers
 *      and reassembles TCP segments so the verdict program is always invoked
 *      with one complete message, even when it spans multiple TCP segments
 *      (e.g. a large DNS response or an HTTP body). Without a parser, the
 *      verdict runs on whatever in-order bytes TCP just made available, which
 *      may be a partial message.
 *   5. (optionally) Write a SEC("sk_msg") program to also observe the data the
 *      client *sends* (the verdict only sees received data). Use
 *      gadget_tcp_stream_msg_lookup(msg) to get the connection. sk_msg reads
 *      its payload via bpf_msg_pull_data() + data/data_end rather than
 *      bpf_skb_load_bytes().
 *
 * Inspektor Gadget attaches these automatically based on their section names:
 * the sock_ops program to the cgroup v2 root (configurable via
 * "programs.gadget_tcp_stream_sockops.cgroup"), and the sk_skb/sk_msg programs
 * to gadget_sockhash (configurable via "programs.<name>.attach_to").
 *
 * Container / Kubernetes enrichment:
 *   Each recorded connection carries a struct gadget_process (conn->proc). For
 *   the active (client) side it is populated with the process that called
 *   connect() -- including its mount namespace -- by a fexit/tcp_connect program
 *   defined here. Copying conn->proc into a gadget event (event->proc) lets
 *   Inspektor Gadget enrich the event with the owning container and Kubernetes
 *   pod metadata. This works even though the sk_skb/sk_msg programs run in a
 *   context where the current process is unknown, because the capture happens
 *   in the connect() syscall context and is correlated to the socket (by cookie
 *   on the receive path, by 4-tuple on the send path). The passive (server)
 *   side has no connect() call, so its conn->proc is left zeroed.
 */

#ifndef __GADGET_TCP_STREAM_H
#define __GADGET_TCP_STREAM_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h> // for BPF_PROG (fexit)
#include <bpf/bpf_core_read.h>

#include <gadget/types.h>
#include <gadget/common.h> // for gadget_process_populate()

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

/*
 * Connection tuple recorded by the sock_ops program. sk_skb programs run in
 * packet/softirq context where reading the socket tuple is awkward, so we stash
 * it here keyed by the (stable) socket cookie, which is identical whether read
 * from a sock_ops or an sk_skb context for the same socket.
 *
 * All addresses are stored in network byte order (matching the format expected
 * by struct gadget_l4endpoint_t). Ports are stored in host byte order.
 *
 * proc holds the owning process (and therefore its mount namespace) captured in
 * process context at connect() time. Copying it into a gadget event lets
 * Inspektor Gadget enrich the event with the container and Kubernetes metadata
 * of the process that opened the connection. It is only populated for the
 * active (client) side of a connection, since that is the only side whose
 * establishment happens in process context; for the passive (server) side the
 * proc fields are left zeroed.
 */
struct gadget_tcp_stream_conn {
	__u8 version; // 4 or 6
	__u8 pad[3];
	__u16 sport; // local port, host byte order
	__u16 dport; // remote port, host byte order
	union {
		__u32 saddr_v4;
		__u8 saddr_v6[16];
	};
	union {
		__u32 daddr_v4;
		__u8 daddr_v6[16];
	};
	struct gadget_process proc;
};

/*
 * gadget_sockhash holds established TCP sockets so that sk_skb stream programs
 * run on their data. It is the default map sk_skb programs are attached to by
 * Inspektor Gadget. The key is the socket cookie.
 */
struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, __u64);
} gadget_sockhash SEC(".maps");

/* Maps socket cookie -> connection tuple. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct gadget_tcp_stream_conn);
} gadget_tcp_stream_conns SEC(".maps");

/*
 * Connection 4-tuple, used as an alternative index into the connection table
 * for the sk_msg (send) path. sk_msg programs cannot obtain the socket cookie
 * (bpf_get_socket_cookie is not available there), but they do have the socket
 * tuple in the sk_msg_md context, so we index the connection by that tuple.
 *
 * Ports are host byte order, addresses network byte order -- matching the
 * fields read from both struct bpf_sock_ops and struct sk_msg_md.
 */
struct gadget_tcp_stream_tuple {
	__u8 version; // 4 or 6
	__u8 pad[3];
	__u16 sport;
	__u16 dport;
	__u8 saddr[16];
	__u8 daddr[16];
};

/*
 * Maps connection tuple -> connection.
 *
 * This stores the full connection (not just the socket cookie) so the sk_msg
 * send path resolves it with a single map lookup. Indexing the tuple to a
 * cookie and then chaining a second lookup into gadget_tcp_stream_conns would
 * cross two independent LRU_HASH maps that evict on their own, so one could drop
 * an entry the other still held and leave sent data unattributed. Keeping a
 * self-contained copy here means each lookup path touches exactly one LRU map,
 * so they cannot diverge. The cost is a second copy of the connection and
 * mirroring the process enrichment into it (see gadget_tcp_stream_connect).
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct gadget_tcp_stream_tuple);
	__type(value, struct gadget_tcp_stream_conn);
} gadget_tcp_stream_tuples SEC(".maps");

/*
 * GADGET_TCP_STREAM_BUILD_TUPLE fills a gadget_tcp_stream_tuple from a context
 * that exposes the standard socket fields. Both struct bpf_sock_ops (sock_ops)
 * and struct sk_msg_md (sk_msg) share these field names and byte-order
 * conventions: local_port is host byte order, remote_port is network byte order
 * stored in a __u32 (so bpf_ntohl yields the host-order port), and addresses
 * are network byte order. Using the exact same extraction on both sides
 * guarantees the keys match.
 */
#define GADGET_TCP_STREAM_BUILD_TUPLE(ctx, t)                    \
	do {                                                     \
		__builtin_memset(&(t), 0, sizeof(t));            \
		(t).sport = (__u16)(ctx)->local_port;            \
		(t).dport = (__u16)bpf_ntohl((ctx)->remote_port); \
		if ((ctx)->family == AF_INET6) {                 \
			(t).version = 6;                         \
			__u32 *_s = (__u32 *)(t).saddr;          \
			__u32 *_d = (__u32 *)(t).daddr;          \
			_s[0] = (ctx)->local_ip6[0];             \
			_s[1] = (ctx)->local_ip6[1];             \
			_s[2] = (ctx)->local_ip6[2];             \
			_s[3] = (ctx)->local_ip6[3];             \
			_d[0] = (ctx)->remote_ip6[0];            \
			_d[1] = (ctx)->remote_ip6[1];            \
			_d[2] = (ctx)->remote_ip6[2];            \
			_d[3] = (ctx)->remote_ip6[3];            \
		} else {                                         \
			(t).version = 4;                         \
			*(__u32 *)(t).saddr = (ctx)->local_ip4;  \
			*(__u32 *)(t).daddr = (ctx)->remote_ip4; \
		}                                                \
	} while (0)

/*
 * Gadgets may override this to only track sockets of interest. It is evaluated
 * in sock_ops context with the struct bpf_sock_ops named "skops". By default,
 * every established TCP socket is tracked.
 */
#ifndef gadget_tcp_stream_should_track
#define gadget_tcp_stream_should_track(skops) (1)
#endif

static __always_inline void
gadget_tcp_stream_fill_conn(struct bpf_sock_ops *skops,
			    struct gadget_tcp_stream_conn *conn)
{
	// local_port is host byte order; remote_port is a __be16 whose value ends
	// up in the high 16 bits of the __u32 context field, so bpf_ntohl() (not
	// bpf_ntohs()) yields the host-order port.
	conn->sport = (__u16)skops->local_port;
	conn->dport = (__u16)bpf_ntohl(skops->remote_port);

	if (skops->family == AF_INET6) {
		conn->version = 6;
		__u32 *saddr = (__u32 *)conn->saddr_v6;
		__u32 *daddr = (__u32 *)conn->daddr_v6;
		// Copy each word individually: the verifier only allows
		// fixed-offset scalar loads from the sock_ops context, not a
		// memcpy over it.
		saddr[0] = skops->local_ip6[0];
		saddr[1] = skops->local_ip6[1];
		saddr[2] = skops->local_ip6[2];
		saddr[3] = skops->local_ip6[3];
		daddr[0] = skops->remote_ip6[0];
		daddr[1] = skops->remote_ip6[1];
		daddr[2] = skops->remote_ip6[2];
		daddr[3] = skops->remote_ip6[3];
	} else {
		conn->version = 4;
		conn->saddr_v4 = skops->local_ip4; // already network byte order
		conn->daddr_v4 = skops->remote_ip4;
	}
}

// gadget_tcp_stream_conn_to_tuple derives the tuple key for a connection from
// the connection itself, so the tuple index can be (re)written without a
// sock_ops/sk_msg context. It reproduces exactly what
// GADGET_TCP_STREAM_BUILD_TUPLE writes, so keys match. The address unions in
// conn are zero-padded beyond the v4 field, so copying all 16 bytes is correct
// for both families.
static __always_inline void
gadget_tcp_stream_conn_to_tuple(const struct gadget_tcp_stream_conn *conn,
				struct gadget_tcp_stream_tuple *t)
{
	__builtin_memset(t, 0, sizeof(*t));
	t->version = conn->version;
	t->sport = conn->sport;
	t->dport = conn->dport;
	__builtin_memcpy(t->saddr, conn->saddr_v6, sizeof(t->saddr));
	__builtin_memcpy(t->daddr, conn->daddr_v6, sizeof(t->daddr));
}

// gadget_tcp_stream_record stores the connection under both indexes: by socket
// cookie (used by the sk_skb receive path) and by 4-tuple (used by the sk_msg
// send path, which cannot obtain the cookie).
static __always_inline void
gadget_tcp_stream_record(struct bpf_sock_ops *skops, __u64 cookie)
{
	struct gadget_tcp_stream_conn conn = {};
	gadget_tcp_stream_fill_conn(skops, &conn);
	bpf_map_update_elem(&gadget_tcp_stream_conns, &cookie, &conn, BPF_ANY);

	struct gadget_tcp_stream_tuple t;
	GADGET_TCP_STREAM_BUILD_TUPLE(skops, t);
	bpf_map_update_elem(&gadget_tcp_stream_tuples, &t, &conn, BPF_ANY);
}

SEC("sockops")
int gadget_tcp_stream_sockops(struct bpf_sock_ops *skops)
{
	if (skops->family != AF_INET && skops->family != AF_INET6)
		return 0;

	if (!gadget_tcp_stream_should_track(skops))
		return 0;

	__u64 cookie = bpf_get_socket_cookie(skops);

	switch (skops->op) {
	case BPF_SOCK_OPS_TCP_CONNECT_CB: {
		// Record the connection tuple for the active (client) side and
		// assign the socket cookie (bpf_get_socket_cookie above). The
		// owning process cannot be captured here: sock_ops programs are
		// not allowed to call the bpf_get_current_*() helpers, even
		// though this callback runs in the connecting process' context.
		// Instead, the companion fexit/tcp_connect program below fills
		// in conn->proc using the same cookie, from a context where the
		// current-task helpers are available.
		//
		// The socket is not established yet, so it is not added to the
		// sockhash here; that happens at *_ESTABLISHED_CB below.
		gadget_tcp_stream_record(skops, cookie);
		return 0;
	}
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		// If the connection tuple was not already recorded at connect
		// time (i.e. the passive/server side, which has no connect
		// callback), record it now. The proc fields stay zeroed for the
		// passive side because establishment happens in softirq context.
		if (!bpf_map_lookup_elem(&gadget_tcp_stream_conns, &cookie))
			gadget_tcp_stream_record(skops, cookie);

		// Add the socket to the sockhash so sk_skb stream programs run
		// on its data.
		bpf_sock_hash_update(skops, &gadget_sockhash, &cookie,
				     BPF_NOEXIST);
		return 0;
	default:
		return 0;
	}
}

/*
 * gadget_tcp_stream_connect captures the process that opened an active (client)
 * connection so its container / Kubernetes metadata can enrich the events
 * produced by the sk_skb program. It runs on the return of tcp_connect(), i.e.
 * still in the connecting process' syscall context (so the bpf_get_current_*()
 * helpers are valid) and after the sock_ops TCP_CONNECT_CB above has already
 * recorded the connection tuple and assigned the socket cookie. We correlate
 * the two via that cookie, read here from sk->sk_cookie.
 *
 * This only covers the active (client) side. Passive (server) sockets have no
 * connect() call in process context, so their conn->proc is left zeroed.
 */
SEC("fexit/tcp_connect")
int BPF_PROG(gadget_tcp_stream_connect, struct sock *sk, int ret)
{
	if (ret != 0)
		return 0;

	__u64 cookie = BPF_CORE_READ(sk, __sk_common.skc_cookie.counter);
	if (cookie == 0)
		return 0;

	struct gadget_tcp_stream_conn *conn =
		bpf_map_lookup_elem(&gadget_tcp_stream_conns, &cookie);
	if (!conn)
		return 0; // socket not tracked (e.g. not a port we care about)

	gadget_process_populate(&conn->proc);

	// Mirror the populated process info into the tuple-indexed copy used by
	// the sk_msg send path, so both lookup paths return identical enrichment.
	struct gadget_tcp_stream_tuple t;
	gadget_tcp_stream_conn_to_tuple(conn, &t);
	bpf_map_update_elem(&gadget_tcp_stream_tuples, &t, conn, BPF_ANY);
	return 0;
}

/*
 * gadget_tcp_stream_lookup returns the connection tuple recorded for the socket
 * this skb belongs to, or NULL if the socket was not tracked.
 */
static __always_inline struct gadget_tcp_stream_conn *
gadget_tcp_stream_lookup(struct __sk_buff *skb)
{
	__u64 cookie = bpf_get_socket_cookie(skb);
	return bpf_map_lookup_elem(&gadget_tcp_stream_conns, &cookie);
}

/*
 * gadget_tcp_stream_msg_lookup is the sk_msg (send path) counterpart of
 * gadget_tcp_stream_lookup. sk_msg programs cannot read the socket cookie, so
 * the connection is looked up via its 4-tuple (recorded by the sock_ops
 * program) instead.
 */
static __always_inline struct gadget_tcp_stream_conn *
gadget_tcp_stream_msg_lookup(struct sk_msg_md *msg)
{
	struct gadget_tcp_stream_tuple t;
	GADGET_TCP_STREAM_BUILD_TUPLE(msg, t);
	return bpf_map_lookup_elem(&gadget_tcp_stream_tuples, &t);
}

#endif /* __GADGET_TCP_STREAM_H */
