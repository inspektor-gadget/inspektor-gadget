---
name: kubernetes-troubleshooting
description: >-
  Debug live Kubernetes workloads at the kernel level with Inspektor Gadget via
  `kubectl gadget run`. Use when a pod or Service is misbehaving and application
  logs are not enough: DNS resolution failures or slow lookups, TCP connection
  resets / retransmits / drops / refused connections, CrashLoopBackOff, "no such
  file or directory", permission / capability / seccomp / LSM denials, OOMKilled,
  unexpected process execs, slow disk or file I/O, or "which pod/process made
  this syscall / connection / DNS query". Traces real kernel events with eBPF,
  auto-enriched with pod / namespace / container / node. Read-only, no workload
  changes. Not for plain application logs, long-term metrics dashboards, or
  editing cluster state.
compatibility: >-
  Requires the `kubectl gadget` plugin locally and an in-cluster Inspektor Gadget
  DaemonSet (`kubectl gadget deploy`, namespace `gadget`), on a cluster where you
  hold troubleshooting RBAC and nodes with BTF for CO-RE. Read-only. If the plugin
  or DaemonSet is missing, see references/install.md — ask the operator before
  installing.
---

# Kubernetes troubleshooting with Inspektor Gadget

Inspektor Gadget (IG) runs **eBPF programs** in the kernel to trace live events —
syscalls, network packets, DNS, capability checks, OOM kills — and **enriches
every event with Kubernetes metadata** (namespace, pod, container, node). You
drive it with `kubectl gadget run <gadget>:latest`. Each **gadget** is an OCI
image pulled on demand; there is **no built-in list of gadgets to memorize** and
no `list-gadgets` command.

Use IG when logs/metrics can't answer *"what is the kernel actually doing for
this workload right now?"* — e.g. a request times out but the app logs nothing,
a file open fails silently, a connection is reset before the app sees it.

## Prerequisite: confirm IG is available (check first, then route)

This skill drives `kubectl gadget`. Confirm it's usable before the loop:

```bash
command -v kubectl-gadget >/dev/null 2>&1 || echo "kubectl gadget plugin MISSING"
kubectl gadget version    # "Server version: not available" = inspect the gadget namespace
```

If the plugin is **missing** or the server version is unavailable, **open
`references/install.md` and follow it** — don't guess an install command.
Installing the plugin and running `kubectl gadget deploy` need cluster rights and
start a **privileged DaemonSet**, so **ask the operator before installing**.

## The one rule: discover, don't guess

**Never hardcode a gadget's flags or field names from memory.** Gadget images
evolve and new gadgets ship. Always enumerate the real interface at run time:

```bash
kubectl gadget run <gadget>:latest -h          # flags + a "--fields" block listing every data source & field
kubectl gadget run <gadget>:latest -A --timeout 5 -o json \
  | jq -s '(.[0] // {}) | if type == "array" then (.[0] // {}) else . end | keys'
```

The gadget's own `-h`/`--fields` output is the source of truth, so this skill
never drifts from the shipped gadgets. If a symptom below names a gadget, still
confirm its flags/fields with `-h` before relying on them. See
`references/discovering-params-and-fields.md`.

## The loop (repeat until root cause)

1. **Route.** Map the symptom to a *domain* (networking / security /
   process-lifecycle / storage-fs / performance), then to a candidate gadget
   using the table below and the matching `references/domain-*.md`.
2. **Discover.** Run `<gadget>:latest -h` to read the real flags and fields.
3. **Run bounded.** Always scope and time-box:
   `kubectl gadget run <gadget>:latest -n <ns> --timeout <sec> -o json`
   (`-n`/`-p`/`-c` to filter; **always set `--timeout`** for streaming gadgets;
   `--max-entries` for `top`/`snapshot`). See `references/common-flags.md`.
4. **Read the columns.** Inspect the enriched fields (`k8s.*`, `proc.*`, error
   codes) to confirm or refute a hypothesis, then narrow scope and repeat.

## Symptom → first gadget (confirm flags/fields with `-h`)

| Symptom (what the user reports) | Domain | Start with | Then / disambiguate |
|---|---|---|---|
| DNS fails, slow, or NXDOMAIN | networking | `trace_dns` | latency in `latency_ns`; see domain-networking |
| Connection reset / refused / hangs | networking | `trace_tcp` | `trace_tcpretrans` (retransmits), `trace_tcpdrop` (kernel drops) |
| Packet loss / high latency between pods | networking | `trace_tcpdrop` | `profile_tcprtt`, `top_tcp`, `tcpdump` |
| TLS/cert/SNI routing issue | networking | `trace_sni` | `trace_ssl` (plaintext at TLS boundary) |
| Port bind fails / "address already in use" | networking | `snapshot_socket` | `trace_bind` (the failing bind + errno) |
| CrashLoopBackOff / unexpected restarts | process-lifecycle | `trace_exec` | `trace_signal` (filter `--signal 9/15` — Go SIGURG / glibc SIGRTMIN async-preempt noise), `trace_oomkill` |
| Killed / OOMKilled | process-lifecycle | `trace_oomkill` | `top_process`, `profile_cpu` |
| Container died too fast to trace live (post-mortem) | process-lifecycle | `traceloop` | replays recent syscalls from the ring buffer; empty if it wasn't already recording |
| Watch an interactive shell / tty / pts / keystrokes | process-lifecycle | `ttysnoop` | no `--tty`/`--pts` selector — scope by `--pid`/`--comm`/pod |
| "no such file" / missing config / wrong path | storage-fs | `trace_open` | `snapshot_file`, `top_file` |
| Slow disk / file I/O | storage-fs | `trace_fsslower` | `profile_blockio`, `top_blockio` |
| Unexpected mount/umount, or suspicious hardlink/symlink (escape) | storage-fs | `trace_mount` | `trace_link` (`type` = HARDLINK/SYMLINK cuts the noise) |
| fd leak / "too many open files" / inotify watch storm | storage-fs | `fdpass` | `fsnotify`; `snapshot_file` (unclosed fds in one proc) |
| Permission denied despite correct RBAC/FS | security | `trace_capabilities` | `audit_seccomp`; node audit logs for AppArmor/SELinux |
| Seccomp denial | security | `audit_seccomp` | the `code` + syscall identify the seccomp action; `advise_seccomp` to author a profile |
| AppArmor/SELinux denial | security | node audit logs | `trace_lsm` can correlate hook activity, but does not expose another LSM's verdict |
| Kernel module loaded / rootkit / unexpected insmod | security | `trace_init_module` | `trace_capabilities` (CAP_SYS_MODULE) |
| Harden / author a seccomp or NetworkPolicy profile | security | `advise_seccomp` | `advise_networkpolicy` (policy from observed traffic) |
| High CPU, or slow despite low CPU% (CFS throttling / cgroup CPU limit) | performance | `profile_cpu` | `top_cpu_throttle` (capped?), `top_process` |
| Memory growth / leak (userspace) | performance | `trace_malloc` (libc malloc only — statically-linked Go runtime allocator invisible) | `trace_malloc --collect-ustack` (the leak site) |
| App hung / mutex deadlock | performance | `deadlock` (pthread only — Go `sync.Mutex` invisible) | `profile_cpu` |
| GPU / CUDA out-of-memory | performance | `top_cuda_memory` | per-proc device vs pinned; `profile_cuda` = libcuda Driver-API alloc/free |
| Quantify eBPF/gadget CPU or memory overhead (self-profiling) | meta | `bpfstats` | needs an active window — use a longer `--timeout` |

This is a deliberately **thin shortlist, not the catalog** — it names the few
gadgets that fit the most common symptoms so you don't scan the full bundled set,
keeping this always-loaded router small. **Symptom not listed here,
or unsure which row fits?** Open `references/gadget-catalog.md` — it groups **all
bundled** gadgets by domain with the disambiguation reasoning. The authoritative live
list is whatever `kubectl gadget run <name>:latest -h` resolves; always confirm a
gadget's flags/fields there before relying on them.

## References (load only the one you need)

- `references/gadget-catalog.md` — all upstream gadgets grouped by domain, one line each.
- `references/discovering-params-and-fields.md` — the discover-don't-guess mechanics.
- `references/common-flags.md` — filters, output modes, timeouts, gotchas.
- `references/domain-networking.md` — DNS / TCP / drops / retransmits / TLS-SNI / NetworkPolicy.
- `references/domain-security.md` — capabilities / LSM / seccomp / module loading.
- `references/domain-process-lifecycle.md` — exec / signals / OOM / snapshots / syscall recording.
- `references/domain-storage-fs.md` — open / slow FS / block I/O / mounts / fd / fsnotify.
- `references/domain-performance.md` — CPU / throttle / RTT / deadlock / malloc / GPU.
- `references/install.md` — detect whether IG is usable; install the `kubectl gadget` plugin and deploy the DaemonSet if missing.

## Safety

Observation is **read-only** — gadgets trace, they never modify workloads. They
require a privileged in-cluster IG (DaemonSet) or `kubectl gadget`, so use them
in clusters where you have troubleshooting rights. Always bound streaming
gadgets with `--timeout` and cap `top`/`snapshot` with `--max-entries` so a
trace can't flood your context or the API server.
