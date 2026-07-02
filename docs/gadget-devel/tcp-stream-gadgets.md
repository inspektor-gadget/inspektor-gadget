---
title: 'Parsing TCP-stream protocols'
sidebar_position: 315
description: 'Build gadgets that parse application protocols carried over TCP (DNS-over-TCP, HTTP, ...) using sock_ops, sk_skb and sk_msg'
---

Some application protocols are carried over TCP: DNS-over-TCP, HTTP, Redis,
PostgreSQL, and many more. Observing them from a classic socket filter or TC
program is awkward, because those see **individual packets** before TCP
reassembly: a single application message can be split across several TCP
segments, arrive out of order, or be retransmitted.

Inspektor Gadget provides a small, reusable header,
[`<gadget/tcp_stream.h>`](https://github.com/inspektor-gadget/inspektor-gadget/blob/%IG_BRANCH%/include/gadget/tcp_stream.h),
that lets a gadget parse the **reassembled, in-order TCP byte stream** instead.
It builds on three eBPF program types — `sock_ops`, `sk_skb` and `sk_msg` — and
wires up container/Kubernetes enrichment for you.

## Where does TCP reassembly happen?

It happens in the kernel's TCP stack, **before** your program runs. The
`sk_skb`/`sk_msg` programs hook a socket's data path *after* TCP has already put
the bytes in order, removed duplicates, and acknowledged them. By the time your
program sees the data it is a clean application byte stream — exactly what you
need to parse a protocol.

```
NIC → IP → TCP   ← segmentation, ordering, retransmit, dedup handled HERE
                    (this is "TCP reassembly")
                        │
                        ▼
              socket is in a sockhash map  →  custom sk_prot installed
                        │
          ┌─────────────┴─────────────┐
          │ receive path              │ send path
          ▼                           ▼
   sk_skb stream_parser        sk_msg  (runs on sendmsg)
   sk_skb stream_verdict
          │                           │
     SK_PASS/DROP/REDIRECT       SK_PASS/DROP
          ▼                           ▼
   userspace recv()            the wire
```

## The three program types

| Program type | Section name | Runs on | Purpose |
|--------------|--------------|---------|---------|
| `sock_ops` | `sockops` | TCP lifecycle events (connect, established) | Add sockets to the sockhash; record the connection tuple and owning process |
| `sk_skb` stream_parser | `sk_skb/stream_parser` | received stream | Frame the byte stream into complete messages (optional but recommended) |
| `sk_skb` stream_verdict | `sk_skb/stream_verdict` | received stream | Parse the protocol; decide `SK_PASS`/`SK_DROP` |
| `sk_msg` | `sk_msg` | sent stream (`sendmsg`) | Observe what the socket sends |

A `stream_verdict` only sees data **received** by the socket. To also observe
what the client **sends** (e.g. a request/query), add an `sk_msg` program.
Returning `SK_PASS` from either means "deliver the data normally" — the gadget
observes without disrupting traffic.

## What the header gives you

Including `<gadget/tcp_stream.h>` defines:

- **`gadget_sockhash`** — a `BPF_MAP_TYPE_SOCKHASH`. `sk_skb`/`sk_msg` programs
  are attached to this map by default. The `sock_ops` program adds established
  TCP sockets to it.
- **`struct gadget_tcp_stream_conn`** — the recorded connection: version, source
  and destination address/port, and a `struct gadget_process proc` used for
  enrichment.
- **`SEC("sockops") gadget_tcp_stream_sockops`** — records each connection and
  adds it to the sockhash. You do not write this yourself.
- **`SEC("fexit/tcp_connect") gadget_tcp_stream_connect`** — captures the
  process that opened the connection (see [Enrichment](#container--kubernetes-enrichment)).
- **`gadget_tcp_stream_lookup(skb)`** — from an `sk_skb` program, return the
  `struct gadget_tcp_stream_conn *` for the current socket (or `NULL`).
- **`gadget_tcp_stream_msg_lookup(msg)`** — the `sk_msg` equivalent.
- **`gadget_tcp_stream_should_track(skops)`** — an optional macro you `#define`
  *before* including the header to restrict which sockets are tracked.

## Step-by-step: a DNS-over-TCP gadget

The following builds a gadget that traces DNS-over-TCP queries and responses.
DNS-over-TCP frames each message as a 2-byte length prefix followed by the DNS
message ([RFC 7766](https://datatracker.ietf.org/doc/html/rfc7766)).

### 1. Restrict tracked sockets and include the header

Define `gadget_tcp_stream_should_track` (evaluated in `sock_ops` context, with a
`struct bpf_sock_ops *` named `skops`) **before** the include. Here we track
only port 53:

```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/types.h>

// remote_port is network byte order in a __u32, so use bpf_ntohl().
#define gadget_tcp_stream_should_track(skops)             \
	((__u16)(skops)->local_port == 53 ||              \
	 (__u16)bpf_ntohl((skops)->remote_port) == 53)

#include <gadget/tcp_stream.h>
#include <gadget/filter.h>
```

Including `<gadget/filter.h>` gives the gadget the standard Inspektor Gadget
filters (`-c`/`--containername`, `--podname`, `--pid`, `--tid`, `--uid`,
`--gid`, `--comm`, ...) for free. The `sk_skb`/`sk_msg` programs run in a context
where the current process is unknown, so the filters cannot be evaluated against
the *current* task; instead we evaluate them against the process captured at
`connect()` time in `conn->proc` (see [Enrichment](#container--kubernetes-enrichment)).
Define a small helper that we will call from both the verdict and the `sk_msg`
program:

```c
// Applies the standard Inspektor Gadget filters (container / mount namespace,
// pid, tid, uid, gid, comm) to a connection using the process captured at
// connect() time. This is what makes -c/--containername, --podname, --pid, etc.
// take effect. conn->proc is only populated for the active (client) side; the
// passive (server) side has a zeroed mntns_id and is therefore dropped whenever
// any filter is active, which is expected since it cannot be attributed to a
// container.
static __always_inline bool
should_discard(struct gadget_tcp_stream_conn *conn)
{
	struct gadget_process *p = &conn->proc;
	return gadget_should_discard_data(p->mntns_id, p->pid, p->tid, p->comm,
					  p->creds.uid, p->creds.gid);
}
```

### 2. Define the event and the ring buffer

Add a `struct gadget_process proc` field so events get container/Kubernetes
enrichment automatically:

```c
#define DNS_NAME_MAX 256
#define TCP_DNS_LEN_PREFIX 2 // 2-byte length prefix in DNS-over-TCP

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc; // enables container/k8s enrichment
	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;
	__u16 id;
	char qr[2]; // "Q" or "R"
	__u16 qtype_raw;
	char name[DNS_NAME_MAX];
};

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(dns_tcp, events, event);
```

### 3. Frame messages with a stream parser (recommended)

The parser returns the length of the next complete message. `strparser` then
reassembles TCP segments until that many bytes are available before invoking the
verdict — so a large response split across segments is delivered as one message:

```c
SEC("sk_skb/stream_parser")
int dns_tcp_parser(struct __sk_buff *skb)
{
	if (skb->len < TCP_DNS_LEN_PREFIX)
		return 0; // need more data to read the length prefix

	__u16 msg_len;
	if (bpf_skb_load_bytes(skb, 0, &msg_len, sizeof(msg_len)))
		return 0;

	return TCP_DNS_LEN_PREFIX + bpf_ntohs(msg_len);
}
```

The parser return value is: `>0` the length of a complete message; `0` when more
data is needed to determine the length; `<0` on error.

### 4. Parse received data (the response) with a stream verdict

Use `gadget_tcp_stream_lookup(skb)` to recover the connection, copy its `proc`
into the event for enrichment, and return `SK_PASS` to leave the data untouched:

```c
struct dnshdr {
	__u16 id;
	__u16 flags;
	__u16 qdcount, ancount, nscount, arcount;
};

SEC("sk_skb/stream_verdict")
int dns_tcp_verdict(struct __sk_buff *skb)
{
	if (skb->len < TCP_DNS_LEN_PREFIX + sizeof(struct dnshdr))
		return SK_PASS;

	struct gadget_tcp_stream_conn *conn = gadget_tcp_stream_lookup(skb);
	if (!conn)
		return SK_PASS; // socket not tracked

	if (should_discard(conn))
		return SK_PASS; // filtered out (e.g. different container)

	struct dnshdr hdr;
	if (bpf_skb_load_bytes(skb, TCP_DNS_LEN_PREFIX, &hdr, sizeof(hdr)))
		return SK_PASS;

	struct event *event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return SK_PASS;

	event->timestamp_raw = bpf_ktime_get_boot_ns();
	event->proc = conn->proc; // container/k8s enrichment
	event->id = bpf_ntohs(hdr.id);
	event->qr[0] = (bpf_ntohs(hdr.flags) & 0x8000) ? 'R' : 'Q';
	event->qr[1] = '\0';
	// src/dst come from the connection recorded by sock_ops:
	event->src.version = event->dst.version = conn->version;
	event->src.proto_raw = event->dst.proto_raw = IPPROTO_TCP;
	event->src.port = conn->sport;
	event->dst.port = conn->dport;
	event->src.addr_raw.v4 = conn->saddr_v4; // (handle v6 similarly)
	event->dst.addr_raw.v4 = conn->daddr_v4;
	// ... parse the question name into event->name via bpf_skb_load_bytes ...

	gadget_submit_buf(skb, &events, event, sizeof(*event));
	return SK_PASS;
}
```

### 5. Observe sent data (the query) with sk_msg

The verdict only sees received data, so the outgoing query needs an `sk_msg`
program. `sk_msg` cannot read the socket cookie or the current task, so it looks
up the connection by 4-tuple via `gadget_tcp_stream_msg_lookup(msg)`, and reads
its payload through `bpf_msg_pull_data()` + `data`/`data_end`:

```c
SEC("sk_msg")
int dns_tcp_msg(struct sk_msg_md *msg)
{
	if (msg->size < TCP_DNS_LEN_PREFIX + sizeof(struct dnshdr))
		return SK_PASS;

	struct gadget_tcp_stream_conn *conn = gadget_tcp_stream_msg_lookup(msg);
	if (!conn)
		return SK_PASS;

	if (should_discard(conn))
		return SK_PASS; // filtered out (e.g. different container)

	// Make the leading bytes linearly accessible.
	__u32 pull = TCP_DNS_LEN_PREFIX + sizeof(struct dnshdr);
	if (bpf_msg_pull_data(msg, 0, pull, 0))
		return SK_PASS;

	__u8 *data = (__u8 *)(long)msg->data;
	__u8 *data_end = (__u8 *)(long)msg->data_end;
	if (data + pull > data_end)
		return SK_PASS;

	struct dnshdr *hdr = (struct dnshdr *)(data + TCP_DNS_LEN_PREFIX);

	struct event *event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return SK_PASS;

	event->timestamp_raw = bpf_ktime_get_boot_ns();
	event->proc = conn->proc;
	event->id = bpf_ntohs(hdr->id);
	event->qr[0] = 'Q';
	event->qr[1] = '\0';
	// ... fill src/dst from conn and parse the name from [data, data_end) ...

	gadget_submit_buf(msg, &events, event, sizeof(*event));
	return SK_PASS;
}

char _license[] SEC("license") = "GPL";
```

:::note
Reading the payload in an `sk_skb` program uses `bpf_skb_load_bytes()` with
arbitrary offsets. An `sk_msg` program instead uses `bpf_msg_pull_data()` to
linearize a range and then reads through the `data`/`data_end` pointers with
bounds checks. `sk_msg` has no stream parser, so it sees one `sendmsg` at a time;
this is fine for small requests sent in a single write.
:::

### 6. Metadata

A minimal `gadget.yaml`; the `proc` field drives enrichment automatically:

```yaml
name: trace dns_tcp
description: trace DNS-over-TCP using sock_ops + sk_skb + sk_msg
datasources:
  dns_tcp:
    fields:
      src:
        annotations: { template: l4endpoint }
      dst:
        annotations: { template: l4endpoint }
      name:
        annotations: { description: Domain name being queried }
```

## Container / Kubernetes enrichment

Any event that contains a `struct gadget_process` (with a valid `mntns_id`) is
automatically enriched by Inspektor Gadget with the owning container and, in
Kubernetes, the pod name, namespace and labels.

The challenge is that `sk_skb` and `sk_msg` run in a context where the current
process is unknown, and — like `sock_ops` — they are not allowed to call the
`bpf_get_current_*()` helpers. The header solves this for the **active (client)
side**:

1. A `SEC("fexit/tcp_connect")` program (included in the header) runs in the
   connecting process' `connect()` syscall context, where the current task and
   its mount namespace are known. It fills `conn->proc` via
   `gadget_process_populate()`.
2. It is correlated to the connection recorded by `sock_ops` via the socket
   cookie.
3. Your `sk_skb`/`sk_msg` program copies `conn->proc` into the event; the
   receive path finds the connection by cookie, the send path by 4-tuple.

The **passive (server) side** has no `connect()` call in process context, so its
`conn->proc` is left zeroed and such events are not process-enriched.

### Container and process filtering

Because `conn->proc` carries the owning process' `mntns_id`, `pid`, `uid`, etc.,
the same connection info that drives enrichment also drives the standard
Inspektor Gadget filters. Including `<gadget/filter.h>` and calling
`gadget_should_discard_data()` on `conn->proc` (the `should_discard()` helper in
[step 1](#1-restrict-tracked-sockets-and-include-the-header)) makes flags like
`-c`/`--containername`, `--podname`, `--pid`, `--uid` and `--comm` take effect —
for example, restricting the trace to a single container's DNS traffic. Since
only the active (client) side has a populated `conn->proc`, the passive (server)
side is dropped whenever any filter is active, which is expected as it cannot be
attributed to a container.

## Attachment and configuration

Inspektor Gadget attaches the programs automatically from their section names:

- `sock_ops` is attached to the **cgroup v2 root** by default (so it observes
  every socket on the host). Override the cgroup per program with the
  `programs.gadget_tcp_stream_sockops.cgroup` configuration key.
- `sk_skb`/`sk_msg` are attached to the **`gadget_sockhash`** map by default.
  Override the target map per program with `programs.<name>.attach_to`.

## Requirements and caveats

- Kernel ≥ 5.7 (socket cookie in `sock_ops`, `BPF_MAP_TYPE_SOCKHASH`).
- Kernel BTF is required for the `fexit/tcp_connect` enrichment program.
- Only newly established connections are observed; sockets that already existed
  when the gadget started are not added to the sockhash.
- Process/container enrichment covers the active (client) side only.
- Returning `SK_PASS` keeps traffic flowing; the gadget is observe-only unless
  you deliberately return `SK_DROP`.

## See also

- [eBPF Program Types](./program-types.md) — reference for `sockops`, `sk_skb` and
  `sk_msg` section names.
- [eBPF API](./gadget-ebpf-api.md) — enriched types, `struct gadget_process`,
  `struct gadget_l4endpoint_t`, ring-buffer helpers.
