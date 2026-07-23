# Gadget catalog — upstream gadgets grouped by domain (`ig` variant)

The authoritative live interface for any gadget is `sudo ig run <gadget>:latest
--help` (see `discovering-params-and-fields.md`). This catalog is a **routing
aid**: it groups the shipped upstream gadgets so you can pick the right one for a
symptom, then confirm its flags/fields with `--help`. One-liners are the gadgets'
own descriptions. Gadgets are OCI images; there is no `list-gadgets` command.
This catalog tracks the upstream `gadgets/` tree at the time it is updated.
Recheck that tree and the release catalog when editing it; a generated drift
check can be added separately.

> Run form: `sudo ig run <gadget>:latest …`. The same gadgets also run under
> `kubectl gadget run …` in a cluster (see `kubernetes-companion.md`).

## Networking

| Gadget | What it traces |
|---|---|
| `trace_dns` | DNS requests/responses (query name, qtype, rcode, latency_ns) |
| `trace_tcp` | connect / accept / close of TCP connections |
| `trace_tcpretrans` | TCP retransmissions (congestion / loss) |
| `trace_tcpdrop` | TCP packets dropped by the kernel (with drop reason / stack) |
| `trace_sni` | TLS SNI (Server Name Indication) on the wire |
| `trace_ssl` | OpenSSL/GnuTLS read/recv/write/send (plaintext at TLS boundary) |
| `trace_bind` | socket bind() calls (who bound which port) |
| `snapshot_socket` | point-in-time list of open TCP/UDP sockets (src, dst, state, inode, netns) |
| `top_tcp` | periodic per-connection TCP activity |
| `profile_tcprtt` | histogram of TCP round-trip time |
| `profile_qdisc_latency` | network scheduler (qdisc) latency |
| `tcpdump` | capture raw packets — write with `-o pcap-ng >file` (no `-w`) |
| `advise_networkpolicy` | K8s NetworkPolicies from observed traffic (**`kubectl gadget` only** — needs pod/podIP metadata; no useful output under `sudo ig`) |

## Security

| Gadget | What it traces |
|---|---|
| `trace_capabilities` | capability checks (which CAP_* tested, allowed/denied) |
| `trace_lsm` | LSM hook invocations (activity only; it does not expose another LSM's verdict) |
| `audit_seccomp` | seccomp audit events with syscall and return code/action |
| `advise_seccomp` | suggest a seccomp profile from observed syscalls |
| `trace_init_module` | init_module/finit_module — kernel module loads |

## Process lifecycle

| Gadget | What it traces |
|---|---|
| `trace_exec` | process executions (argv, cwd) |
| `trace_signal` | signals delivered (who signalled whom) |
| `trace_oomkill` | OOM-killer events (victim `tcomm`/`tpid`; trigger `fprocess.*`; memcg) |
| `snapshot_process` | point-in-time list of running processes |
| `top_process` | periodic process statistics |
| `traceloop` | syscall flight recorder — replay a container's last syscalls |
| `ttysnoop` | watch live output from a tty/pts device |

## Storage & filesystem

| Gadget | What it traces |
|---|---|
| `trace_open` | file opens (fname, flags, error) — `--failed` for only failures |
| `trace_fsslower` | open/read/write/fsync slower than `--min` µs (per `--filesystem`) |
| `snapshot_file` | point-in-time list of open files |
| `top_file` | periodic per-file activity (`--all-files` for non-regular) |
| `profile_blockio` | histogram of block-device I/O latency |
| `top_blockio` | periodic block-device I/O activity |
| `trace_mount` | mount()/umount() syscalls |
| `trace_link` | hardlink / symlink creation |
| `fdpass` | fd passing over unix sockets (SCM_RIGHTS) |
| `fsnotify` | inotify/fanotify events |

## Performance

| Gadget | What it traces |
|---|---|
| `profile_cpu` | sampled stacks → on-CPU flamegraph (`--user/kernel-stacks-only`) |
| `top_cpu_throttle` | cgroup CFS CPU throttling (containers hitting CPU limits) |
| `trace_malloc` | libc malloc/free (userspace allocation churn / leak) |
| `deadlock` | pthread_mutex lock/unlock ordering → potential deadlocks |
| `profile_cuda` | CUDA allocations in libcuda (Driver API) |
| `top_cuda_memory` | per-process CUDA memory alloc/free (device vs pinned host) |

## Meta

| Gadget | What it does |
|---|---|
| `bpfstats` | per-eBPF-program memory/CPU (`runcount`/`runtime`) — needs `sysctl kernel.bpf_stats_enabled=1`; counters read 0 until stats accumulate, so use a longer `--timeout` |

## Disambiguation shortcuts

- Connection problem: `trace_tcp` (events) → `trace_tcpretrans` (loss) → `trace_tcpdrop` (kernel dropped it).
- File problem: `trace_open --failed` (the failing open + errno) vs `top_file`/`snapshot_file` (who's using files now).
- TLS problem: `trace_sni` (which host/SNI) vs `trace_ssl` (the plaintext payload).
- CPU problem: `profile_cpu` (where CPU goes) vs `top_cpu_throttle` (capped by limits) vs `top_process` (who).
- Dying process: `trace_oomkill` (OOM?) → `trace_signal` (signalled, by whom?) → `trace_exec` (did it start, with what argv?).

If a symptom isn't covered here, pick the closest domain gadget and run `--help`
— the field list often reveals whether it fits.

## Third-party / add-on gadgets (not shipped in this catalog)

This catalog lists only the gadgets bundled with the base image. Operators can
install **additional third-party gadget images** from public registries (for
example Artifact Hub — <https://artifacthub.io> — kind "Inspektor Gadget"). Once
pulled, they run exactly like any other gadget and the router should route to
them by symptom.

**Never assume an add-on is absent because it is missing from this table.**
Before concluding a capability is unavailable, DISCOVER what is actually
installed on the host:

```bash
sudo ig image list --no-trunc     # every locally installed gadget image + digest
```

Route to any locally-installed image by its symptom the same way as a bundled
gadget. Third-party images are not normally signed by the official Inspektor Gadget key.
Configure the publisher's trusted public key as documented in the image
verification guide. Do not disable verification merely to make an unknown image
run; `--verify-image=false` is a development-only escape hatch after provenance
has been independently established. Confirm the real flags/fields at run time
with `sudo ig run <full-ref> --help` — do not hardcode them (see
`discovering-params-and-fields.md`).
