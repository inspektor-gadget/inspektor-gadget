# Domain: networking (DNS / TCP / drops / retransmits / TLS-SNI / policy)

Route here for: DNS failures or slow lookups, connection resets/refused/hangs,
packet loss, high latency, TLS/SNI/cert routing issues, "which pod opened this
connection", NetworkPolicy authoring. Confirm every gadget's flags/fields with
`kubectl gadget run <gadget>:latest -h` before relying on them.

## Pick the right gadget (don't conflate the TCP trio)

The single most common mis-route is treating the three TCP gadgets as
interchangeable. They answer different questions:

- **`trace_tcp`** — connection *lifecycle* events: connect / accept / close.
  Use to see **whether** a connection is established, by whom, and if it's
  refused. Has `--connect-only`, `--accept-only`, `--failure-only`.
- **`trace_tcpretrans`** — **retransmissions**. Non-zero retransmits point at
  loss / congestion / a flaky path even when the connection "works".
- **`trace_tcpdrop`** — packets the **kernel dropped**, with the drop reason and
  kernel stack. Use when connections silently stall or reset and you suspect the
  host/network stack (conntrack, buffer, policy) rather than the app.

Rule of thumb: *can't connect* → `trace_tcp`; *connects but slow/lossy* →
`trace_tcpretrans`; *silently dropped/stalled* → `trace_tcpdrop`.

## DNS

```bash
# Watch DNS for one namespace — read fields reliably via json + jq
kubectl gadget run trace_dns:latest -n <ns> --timeout 10 -o json \
  | jq -r '"\(.name)\t\(.qtype)\t\(.rcode)\t\(.latency_ns)"'
```

Read: `rcode` (e.g. NXDOMAIN, SERVFAIL), `latency_ns` (slow resolver), `name`
(is the queried FQDN what you expect — search-domain/ndots surprises show here).
No response row for a query = the request left but nothing came back (upstream
resolver / NetworkPolicy / egress problem — pivot to `trace_tcpdrop` or
`trace_tcp` toward the DNS service IP).

**Gotchas that fake a "no data" result (read before concluding "DNS is fine"):**
- **Never write `-o columns=field,field` — it silently emits ZERO rows.** `-o`
  takes a comma-separated list of output *modes*, so `-o columns=name,latency_ns`
  is parsed as the modes `columns=name`, `latency_ns`, … — each an unknown mode
  (`output mode "latency_ns" … not supported; skipping data source`) and nothing
  prints. Select columns with **`-o columns --fields name,latency_ns`** instead
  (verified live, ig v0.54). For **arithmetic/sort** use the raw sibling
  `latency_ns_raw`; the bare `latency_ns` is a human-formatted string (e.g. "1.2ms")
  — see the `*_raw` convention in `common-flags.md`. `-o json | jq` also works.
- **Benign NXDOMAIN is expected.** libc walks the `search`-domain list per `ndots`,
  so short names legitimately return NXDOMAIN for each search suffix before the real
  FQDN resolves — read the `name` column and ignore the suffix misses; only a
  *final fully-qualified* NXDOMAIN is a genuine failure.
- **Client/server version skew can also yield 0 rows** — see `common-flags.md`
  ("Version skew"): fall back to default output (drop `-o`) and re-run to confirm.

**Mismatched / spoofed answers** (response doesn't match the query, unexpected extra
records): pair request↔response by `id`, then check `num_answers` and the `addresses`
list against `qtype` — an A-query coming back with AAAA/extra records, or a
`num_answers` higher than asked, is the tell. These fields are json-only.

## TCP connectivity

```bash
# Only failed connects in a namespace (why is the app getting connection refused?)
kubectl gadget run trace_tcp:latest -n <ns> --failure-only --timeout 10 -o json
# Retransmissions toward a suspect upstream
kubectl gadget run trace_tcpretrans:latest -n <ns> --timeout 15 -o json
# Kernel drops with reason
kubectl gadget run trace_tcpdrop:latest -A --timeout 15 -o json \
  | jq -r '.reason' | sort | uniq -c
```

Read: `src`/`dst` (+ `.k8s.*` for the peer pod), `error`/errno on failures,
`reason` on drops. A cluster of drops with the same `reason` toward one
`dst.k8s.name` is your smoking gun. `trace_tcpdrop` also exposes `state`,
`tcpflags`, and `kernel_stack` — not only `reason`: for a stalled handshake,
`state=tcp_syn_recv` + `kernel_stack` pinpoint *where* in the stack the SYN-ACK's
ACK died, and `tcpflags` confirms which packet was dropped.

High-signal drop `reason`s (the full ~70-value `SKB_DROP_REASON_*` enum is
discoverable via `kubectl gadget run trace_tcpdrop:latest -h`) → usual root cause:

| `reason` | Usual root cause |
|---|---|
| `SKB_DROP_REASON_NETFILTER_DROP` | conntrack / iptables / NetworkPolicy dropped it |
| `SKB_DROP_REASON_IP_RPFILTER` | asymmetric return path (rp_filter) — reply routed differently |
| `SKB_DROP_REASON_XFRM_POLICY` | IPsec / XFRM policy mismatch (mesh / VPN) |
| `SKB_DROP_REASON_TCP_INVALID_SEQUENCE` | out-of-window segment (NAT/conntrack rewrite, replay) |
| `SKB_DROP_REASON_NO_SOCKET` | nothing listening on that port (wrong pod / not bound yet) |

Reading `reason` alone distinguishes a Cilium/conntrack problem
(`NETFILTER_DROP`) from an asymmetric-routing one (`IP_RPFILTER`) without a
second run.

## Ports & bind failures ("address already in use")

`bind: address already in use` (EADDRINUSE) means something already holds the
port. Two complementary gadgets answer *who* and *catch it live* — confirm both
with `-h` first:

- **`snapshot_socket`** — point-in-time list of open TCP/UDP sockets with
  `state` (LISTEN / ESTABLISHED / TIME_WAIT) and the owning `src`/`dst`/inode.
  Use it to see **who currently holds** the port.
- **`trace_bind`** — live `bind()` calls with `addr` and the errno (`error_raw`).
  Use it to catch **the failing bind as it happens** and which process/container
  attempted it.

```bash
# Who is holding the port right now? (state=LISTEN on that src port = the holder)
kubectl gadget run snapshot_socket:latest -n <ns> -o columns --fields k8s.podName,src,dst,state
# Catch the failing bind() live — EADDRINUSE surfaces in the error field
kubectl gadget run trace_bind:latest -n <ns> --timeout 10 -o json
```

Read: `state=LISTEN` on the same `src` port = the current owner; a `TIME_WAIT`
pileup = recently-closed sockets not yet reaped (missing SO_REUSEADDR / lingering
connections) rather than a live conflict.

## Latency / throughput

- `profile_tcprtt` — RTT histogram; use to prove/refute "the network is slow".
- `top_tcp` — live per-connection throughput; find the noisy connection.
- `profile_qdisc_latency` — scheduler (qdisc) latency if egress shaping is suspected.

## TLS / SNI

- `trace_sni` — the SNI hostname from the **ClientHello** each TLS handshake sends.
  Use for "traffic is going to the wrong backend / cert mismatch / which host is
  this pod calling".
- `trace_ssl` — hooks the OpenSSL/GnuTLS **`SSL_read`/`SSL_write`** boundary
  (read/recv/write/send). Beyond the plaintext payload it surfaces the **library
  call itself**, so it also answers "*which* container's TLS library initiated this
  handshake", not only "what bytes were sent" — don't dismiss it as payload-only.

**Sidecar vs app (same pod, two containers) — the key service-mesh TLS shape.**
When "curl from the app works but the sidecar's TLS fails", scope by container with
`-c <container>` to see which one presents which SNI/cert:

```bash
# What SNI does the app container request vs the istio-proxy sidecar?
kubectl gadget run trace_sni:latest -n <ns> -p <pod> -c <app-container> --timeout 10 -o json
kubectl gadget run trace_sni:latest -n <ns> -p <pod> -c istio-proxy     --timeout 10 -o json
```

`-c` is the discriminator: it isolates the sidecar's handshake from the app's, so
you can see which container is sending the wrong SNI.

## Raw packets & policy

- `tcpdump` — capture pcap when you need packet-level detail an event trace can't
  give (flags, options, payload). Bound it hard with `--timeout`. To write a file
  use the output-mode flag, **`-o pcap-ng >capture.pcapng`** (redirect stdout) —
  there is **no `-w`** flag like classic tcpdump; `-o pcap-ng` selects the pcap-ng
  stream and you redirect it yourself.
- `advise_networkpolicy` — after you understand the traffic, generate a
  NetworkPolicy from what was actually observed. **`kubectl gadget` only** — it
  needs Kubernetes pod/label metadata, so it has no useful output under `sudo ig`
  on a bare host.

## Worked flow: "Service intermittently returns 502"

1. `trace_dns -n <ns>` → is name resolution clean (rcode/ latency)? If not, stop here.
2. `trace_tcp -n <ns> --failure-only` → are connects to the upstream failing/refused?
3. `trace_tcpretrans -n <ns>` → retransmits toward the upstream (loss)?
4. `trace_tcpdrop -A` → kernel drops with a reason (conntrack full, policy)?
5. Correlate the failing `dst.k8s.name` + `reason`/`error` across steps → root cause.

Each step is a **short, scoped, `--timeout`-bounded** run so you never flood
context (irrelevant tokens degrade the agent).
