# Gadget catalog — upstream gadgets grouped by troubleshooting domain

The authoritative live interface for any gadget is `run <gadget>:latest -h`
(see `discovering-params-and-fields.md`). This catalog is a **routing aid**: it
groups the shipped upstream gadgets so you can pick the right one for a symptom,
then confirm its flags/fields with `-h`. One-liners are the gadgets' own
descriptions. Gadgets are OCI images; there is no `list-gadgets` command. This
catalog tracks the upstream `gadgets/` tree at the time it is updated. Recheck
that tree and the release catalog when editing it; a generated drift check can
be added separately.

> Run form: `kubectl gadget run <gadget>:latest …` (Kubernetes) or
> `sudo ig run <gadget>:latest …` (single host). Both accept the same gadgets.

## Networking

| Gadget | What it traces |
|---|---|
| `trace_dns` | DNS requests and responses (query name, qtype, rcode, latency_ns) |
| `trace_tcp` | connect / accept / close events of TCP connections |
| `trace_tcpretrans` | TCP retransmissions (congestion / loss symptom) |
| `trace_tcpdrop` | TCP packets dropped by the kernel (with drop reason / stack) |
| `trace_sni` | TLS SNI (Server Name Indication) seen on the wire |
| `trace_ssl` | data on OpenSSL/GnuTLS read/recv/write/send (plaintext at the TLS boundary) |
| `trace_bind` | socket bind() calls (who bound which port) |
| `snapshot_socket` | point-in-time list of open TCP/UDP sockets (src, dst, state, inode, netns) |
| `top_tcp` | periodic per-connection TCP send/receive activity |
| `profile_tcprtt` | histogram of TCP round-trip time (RTT) |
| `profile_qdisc_latency` | network scheduler (qdisc) latency |
| `tcpdump` | capture raw packets — write with `-o pcap-ng >file` (no `-w`) |
| `advise_networkpolicy` | K8s NetworkPolicies from observed traffic (**`kubectl gadget` only** — needs pod/podIP metadata; no useful output under `sudo ig`) |

## Security (capabilities / LSM / seccomp / module loading)

| Gadget | What it traces |
|---|---|
| `trace_capabilities` | security capability checks (which CAP_* was tested, allowed/denied) |
| `trace_lsm` | LSM hook invocations (activity only; it does not expose another LSM's verdict) |
| `audit_seccomp` | seccomp audit events with syscall and return code/action |
| `advise_seccomp` | suggest a seccomp profile from observed syscalls |
| `trace_init_module` | `init_module`/`finit_module` — kernel module loads |
| `trace_lsm`/`trace_capabilities` | capability verdicts plus LSM hook activity; use node audit logs for AppArmor/SELinux verdicts |

## Process lifecycle (exec / signals / OOM / snapshots / recording)

| Gadget | What it traces |
|---|---|
| `trace_exec` | process executions (argv, cwd) — startup crashes, unexpected binaries |
| `trace_signal` | signals delivered (who SIGKILL'd/SIGTERM'd whom) |
| `trace_oomkill` | OOM-killer events (victim `tcomm`/`tpid`; trigger `fprocess.*`; memcg) |
| `snapshot_process` | point-in-time list of running processes |
| `top_process` | periodic process statistics |
| `traceloop` | syscalls flight recorder — replay the last syscalls of a container |
| `ttysnoop` | watch live output from a tty/pts device |

## Storage & filesystem (open / slow I/O / block / mounts / fd / notify)

| Gadget | What it traces |
|---|---|
| `trace_open` | file opens (fname, flags, error) — "no such file", wrong path, EACCES |
| `trace_fsslower` | open/read/write/fsync slower than a threshold (latency outliers) |
| `snapshot_file` | point-in-time list of open files |
| `top_file` | periodic per-file read/write activity |
| `profile_blockio` | histogram of block-device I/O latency |
| `top_blockio` | periodic block-device I/O activity |
| `trace_mount` | mount()/umount() syscalls |
| `trace_link` | hardlink and symlink creation |
| `fdpass` | file-descriptor passing over unix sockets (SCM_RIGHTS) |
| `fsnotify` | inotify/fanotify events (who is watching what) |

## Performance (CPU / throttle / memory / deadlock / GPU)

| Gadget | What it traces |
|---|---|
| `profile_cpu` | sampled stack traces → on-CPU flamegraph (hot code paths) |
| `top_cpu_throttle` | cgroup CFS CPU throttling (containers hitting CPU limits) |
| `trace_malloc` | libc malloc/free via uprobe (userspace allocation churn/leak) |
| `deadlock` | pthread_mutex lock/unlock ordering → potential deadlock cycles |
| `profile_cuda` | CUDA memory allocations in libcuda (Driver API) |
| `top_cuda_memory` | per-process CUDA memory alloc/free (device vs pinned host) |

## Meta / advisory

| Gadget | What it does |
|---|---|
| `bpfstats` | per-eBPF-program memory/CPU (`runcount`/`runtime`) — needs `sysctl kernel.bpf_stats_enabled=1`; counters read 0 until stats accumulate, so use a longer `--timeout` |
| `advise_seccomp` | (see Security) suggest a seccomp profile |
| `advise_networkpolicy` | (see Networking) suggest NetworkPolicies (`kubectl gadget` only) |

**Disambiguation shortcuts** (see the domain refs for the full reasoning):
- Connection problem: `trace_tcp` (events) → `trace_tcpretrans` (loss) → `trace_tcpdrop` (kernel dropped it).
- File problem: `trace_open` (the open call + errno) vs `top_file`/`snapshot_file` (who's using files now).
- TLS problem: `trace_sni` (which SNI/host) vs `trace_ssl` (the plaintext payload).
- CPU problem: `profile_cpu` (where CPU goes) vs `top_cpu_throttle` (being capped by limits) vs `top_process` (who).

If a symptom isn't covered here, still pick the closest domain gadget and run
`-h` — the field list often reveals whether it fits.
